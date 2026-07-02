#!/usr/bin/env python3
"""End-to-end C2SP tlog-proof demo (v1.3), fully offline with throwaway keys.

Emits a bundle, checkpoints its Merkle root, cosigns with an Ed25519 witness (and an ML-DSA-44
witness when the cryptography build supports it), packs everything into a `.tlog-proof` file and
verifies it — the C2SP "transparent signature" flow.

Run:  python examples/tlog_proof_example.py
"""
from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from proofbundle import checkpoint as cp  # noqa: E402
from proofbundle import emit_bundle, generate_signer  # noqa: E402
from proofbundle.tlogproof import tlog_proof_for_bundle, verify_tlog_proof  # noqa: E402

TS = 1_780_000_000
ORIGIN = "example.com/demo-log"


def raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def main() -> int:
    log_key = generate_signer()
    payload = b'{"suite": "demo", "passed": true}'
    bundle = emit_bundle(payload, log_key, prior_leaves=[b"earlier-entry-1", b"earlier-entry-2"])

    root = base64.b64decode(bundle["merkle"]["root_b64"])
    note = cp.sign_checkpoint(ORIGIN, bundle["merkle"]["tree_size"], root, log_key, ORIGIN)

    witness_vkeys = []
    w_ed = generate_signer()
    note = cp.cosign_checkpoint(note, w_ed, "witness-ed.example/w", TS)
    witness_vkeys.append(cp.cosign_vkey("witness-ed.example/w", raw(w_ed)))

    try:  # ML-DSA-44 witness — post-quantum, only when the build has it (proofbundle[pq])
        from cryptography.hazmat.primitives.asymmetric import mldsa
        w_pq = mldsa.MLDSA44PrivateKey.generate()
        note = cp.cosign_checkpoint_mldsa(note, w_pq, "witness-pq.example/w", TS + 1)
        witness_vkeys.append(
            cp.cosign_vkey_mldsa("witness-pq.example/w", w_pq.public_key().public_bytes_raw()))
        print("ML-DSA-44 witness: available, cosigned")
    except (ImportError, AttributeError):
        print("ML-DSA-44 witness: skipped (cryptography build without PQ)")

    proof = tlog_proof_for_bundle(bundle, note, extra=b"demo context")
    out = os.path.join(os.path.dirname(__file__), "example.tlog-proof")
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(proof)
    print(f"wrote {out}")

    res = verify_tlog_proof(proof, payload, cp.vkey(ORIGIN, raw(log_key)),
                            witness_vkeys, threshold=len(witness_vkeys))
    print(f"log-signature: {res['log_ok']}  witness-quorum: {res['witnesses_ok']}  "
          f"inclusion: {res['inclusion_ok']}")
    print("=> OK" if res["ok"] else "=> FAILED")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
