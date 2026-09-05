#!/usr/bin/env python3
"""Independent check for the companion ONE-LEAF example; not a general CT verifier."""
import base64
import hashlib
import json
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

path = sys.argv[1] if len(sys.argv) > 1 else "receipt.json"
with open(path, encoding="utf-8") as fh:
    r = json.load(fh)

def b64(value):
    return base64.b64decode(value, validate=True)

payload = b64(r["payload_b64"])
pub = b64(r["signature"]["public_key_b64"])
sig = b64(r["signature"]["sig_b64"])
Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)   # raises on failure
print("ed25519 signature over payload bytes: VALID")

m = r["merkle"]
assert m["hash_alg"] == "sha256-rfc6962"
assert m["tree_size"] == 1 and m["leaf_index"] == 0
assert m["inclusion_proof_b64"] == []
root = hashlib.sha256(b"\x00" + payload).digest()              # RFC 6962 leaf hash
stated = b64(m["root_b64"])
print("recomputed RFC 6962 root == stated root:", root == stated)
if root != stated:
    raise SystemExit("root mismatch")
