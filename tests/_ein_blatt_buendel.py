"""A one-leaf evidence bundle with its real signature and root, built in the test instead of by `emit_bundle`.

Since the class fix after 6.5.0, `emit_bundle` refuses a bundle that `verify_bundle` cannot read: it applies the
verifier's structural budget before it signs. A test that asks the VERIFY boundary about a bundle past that budget,
correctly signed, can no longer get one from the emitter. Two tests met this separately (the round-2 review of the
class fix and the test circle at its head); this module is the one builder they share.

`ein_blatt(payload, key)` writes exactly what `emit_bundle(payload, key)` writes for a payload without prior leaves:
same keys, same values, the signature made first and the public key read after it, as `emit_bundle` does. Ed25519
signatures are deterministic, so the two are equal, and `test_ein_blatt_is_what_the_emitter_writes` holds that on an
in-budget payload. It does not check a budget; that is the point of it.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import merkle
from proofbundle.bundle import SCHEMA


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def ein_blatt(payload: bytes, key) -> dict:
    sig = _b64(key.sign(payload))
    pub = _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return {"schema": SCHEMA, "payload_b64": _b64(payload),
            "signature": {"alg": "ed25519", "public_key_b64": pub, "sig_b64": sig},
            "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": 0, "tree_size": 1,
                       "inclusion_proof_b64": [], "root_b64": _b64(merkle.merkle_tree_hash([payload]))}}
