#!/usr/bin/env python3
"""Emit a C2SP tlog-checkpoint (signed note) over a receipt's RFC 6962 Merkle root, and verify it offline.

Makes a receipt witness-network / transparency-log compatible. No new crypto — just RFC 6962 + Ed25519."""
from proofbundle import checkpoint as cp
from proofbundle.emit import _raw_pub, emit_bundle, generate_signer


def main() -> int:
    origin = "proofbundle.example/eval-log"
    signer = generate_signer()
    # take a real bundle's RFC 6962 Merkle root (base64) and decode it for the checkpoint
    bundle = emit_bundle(b"an eval receipt payload", signer)
    root = cp.root_bytes_from_b64(bundle["merkle"]["root_b64"])
    tree_size = bundle["merkle"]["tree_size"]
    signed = cp.sign_checkpoint(origin, tree_size=tree_size, root=root, signer=signer, keyname=origin)
    vkey = cp.vkey(origin, _raw_pub(signer))
    print("--- signed checkpoint ---")
    print(signed, end="")
    print(f"--- vkey ---\n{vkey}")
    r = cp.verify_checkpoint(signed, vkey)
    print(f"verified origin={r['origin']} tree_size={r['tree_size']}")
    print("=> OK" if r["ok"] else "=> FAILED")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
