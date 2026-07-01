#!/usr/bin/env python3
"""Export a receipt as a DSSE-signed in-toto test-result attestation, and verify it (offline).

A generic in-toto verifier reads the `test-result/v0.1` predicate (result PASSED/FAILED, configuration
ResourceDescriptors); the model/dataset stay salted commitments. Needs `pip install "proofbundle[eval]"`."""
from proofbundle import intoto
from proofbundle.emit import _raw_pub, generate_signer
from proofbundle.evalclaim import build_eval_claim


def main() -> int:
    claim, _ = build_eval_claim(suite="arc_easy", suite_version="1", metric="acc", comparator=">=",
                                threshold="0.30", score="0.5567", n=2376, model_id="openai-community/gpt2",
                                dataset_id="allenai/ai2_arc", issuer="", timestamp="2026-07-02T00:00:00Z",
                                provenance={"harness": "lm-evaluation-harness"})
    signer = generate_signer()
    envelope = intoto.export_intoto_dsse(claim, signer, harness={"name": "lm-evaluation-harness", "version": "0.4.12"})
    r = intoto.verify_intoto_dsse(envelope, _raw_pub(signer))
    print(f"predicateType {r['predicate_type']}")
    print(f"result {r['statement']['predicate']['result']}  (payloadType {envelope['payloadType']})")
    print("=> OK" if r["ok"] else "=> FAILED")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
