"""Evidence bundle emitter (v0.2).

Sign a payload with Ed25519 and anchor it as the last leaf of an RFC 6962
Merkle tree, producing a bundle that ``verify_bundle`` accepts. This is the
counterpart to the verifier: create the evidence here, check it anywhere with
``proofbundle verify``, fully offline.

The eval-receipt emitter that builds on this (``emit_eval_receipt``) lives in
:mod:`proofbundle.evalclaim` since v0.4.
"""

from __future__ import annotations

import base64
import os
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from . import merkle
from .bundle import SCHEMA

__all__ = [
    "generate_signer",
    "save_signer",
    "load_signer",
    "emit_bundle",
]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_signer() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 signing key."""
    return Ed25519PrivateKey.generate()


def save_signer(key: Ed25519PrivateKey, path: str) -> None:
    """Write the 32 byte raw Ed25519 private seed to ``path``, mode 0600.

    This is a secret. The file is created owner-read/write only (never
    world-readable, even briefly), so an accidental commit or a shared directory
    does not leak the key. Store it out of version control and treat it like a
    key, not like data.
    """
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    # Open with 0600 from the start to avoid a world-readable window.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


def load_signer(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 signing key from a 32 byte raw seed file."""
    with open(path, "rb") as handle:
        return Ed25519PrivateKey.from_private_bytes(handle.read())


def emit_bundle(
    payload: bytes,
    signer: Ed25519PrivateKey,
    *,
    prior_leaves: Sequence[bytes] = (),
    sd_jwt_vc: Optional[dict] = None,
) -> dict:
    """Produce a ``proofbundle/v0.1`` bundle for ``payload``.

    The payload is signed with ``signer`` and appended as the last leaf of an
    RFC 6962 Merkle tree over ``prior_leaves + [payload]``. The returned dict is
    accepted by :func:`proofbundle.verify_bundle`.

    ``sd_jwt_vc`` is passed through verbatim if given (for example
    ``{"compact": "...", "issuer_public_key_b64": "..."}``).
    """
    leaves = list(prior_leaves) + [payload]
    index = len(leaves) - 1
    root = merkle.merkle_tree_hash(leaves)
    proof = merkle.inclusion_proof(leaves, index)
    signature = signer.sign(payload)

    bundle = {
        "schema": SCHEMA,
        "payload_b64": _b64(payload),
        "signature": {
            "alg": "ed25519",
            "public_key_b64": _b64(_raw_pub(signer)),
            "sig_b64": _b64(signature),
        },
        "merkle": {
            "hash_alg": "sha256-rfc6962",
            "leaf_index": index,
            "tree_size": len(leaves),
            "inclusion_proof_b64": [_b64(p) for p in proof],
            "root_b64": _b64(root),
        },
    }
    if sd_jwt_vc is not None:
        bundle["sd_jwt_vc"] = sd_jwt_vc
    return bundle
