#!/usr/bin/env python3
"""Per-sample audit walkthrough (v1.5 feature, example added v1.6.1), fully offline.

Shows the whole forced-random-sample-check protocol end to end:
  producer:  eval rows  -> build_sample_tree (salted leaves, one holder-kept secret)
                        -> sign the samples root INTO the eval receipt (emit_eval_receipt)
  auditor:   fresh nonce (AFTER seeing the signed receipt) -> audit_challenge -> k indices
  producer:  sample_opening for exactly those indices
  auditor:   verify_sample_opening against the SIGNED root -> OK
  attacker:  swap a sample's disclosure under a challenged index -> verify FAILS

Run:  python examples/persample_audit.py
"""
from __future__ import annotations

import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from proofbundle import generate_signer, verify_bundle  # noqa: E402
from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, emit_eval_receipt  # noqa: E402
from proofbundle.persample import (audit_challenge, build_sample_tree,  # noqa: E402
                                   catch_probability, sample_opening, verify_sample_opening)


def main() -> int:
    # ---- producer side ------------------------------------------------------------------
    tree_secret = secrets.token_bytes(32)          # holder-kept; NEVER goes into the receipt
    rows = [{"id": i, "epoch": 1, "correct": (i % 7 != 0), "answer": chr(65 + i % 4)}
            for i in range(1000)]
    tree = build_sample_tree(rows, tree_secret)
    passed = sum(1 for r in rows if r["correct"])
    score = f"{passed / len(rows):.6f}"

    claim, _salts = build_eval_claim(
        suite="mmlu-demo", suite_version="1.0", metric="accuracy", comparator=">=",
        threshold="0.80", score=score, n=tree["n"], model_id="secret-model-x",
        dataset_id="mmlu-demo", issuer="", timestamp="2026-07-02T12:00:00Z",
        samples={"root_b64": tree["root_b64"], "n": tree["n"], "leaf_alg": tree["leaf_alg"]})
    receipt = emit_eval_receipt(claim, generate_signer())
    assert verify_bundle(receipt).ok
    print(f"receipt signed: accuracy {score} over n={tree['n']}; samples root committed & signed")

    # ---- auditor side -------------------------------------------------------------------
    decoded = decode_eval_claim(receipt)           # verify-side re-checks samples.n == n (v1.6)
    root_b64, n = decoded["samples"]["root_b64"], decoded["samples"]["n"]
    k = 20
    nonce = secrets.token_bytes(16)                # fresh, AFTER seeing the signed receipt
    indices = audit_challenge(root_b64, n, k, nonce)
    print(f"auditor challenges {k} random indices with a fresh nonce: {indices[:8]}...")
    print(f"  (catches 1% doctored samples with probability {catch_probability(0.01, k):.1%})")

    # ---- producer answers, auditor verifies --------------------------------------------
    all_ok = True
    for idx in indices:
        opening = sample_opening(tree["disclosures"], idx)
        res = verify_sample_opening(opening, root_b64, n)
        all_ok = all_ok and res["ok"] and res["record"]["idx"] == idx
    print(f"[{'PASS' if all_ok else 'FAIL'}] all {k} openings verify against the signed root")

    # ---- attacker: swap a sample under a challenged index -------------------------------
    victim = indices[0]
    forged = sample_opening(tree["disclosures"], victim)
    forged["disclosure"] = tree["disclosures"][(victim + 1) % n]   # a different sample's bytes
    swap_caught = not verify_sample_opening(forged, root_b64, n)["ok"]
    print(f"[{'PASS' if swap_caught else 'FAIL'}] swapped-sample opening is rejected")

    ok = all_ok and swap_caught
    print("\n=> OK" if ok else "\n=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
