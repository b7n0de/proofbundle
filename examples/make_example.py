#!/usr/bin/env python3
"""Generate a real, valid example evidence bundle.

Run:  python examples/make_example.py
Then: proofbundle verify examples/example_bundle.json

This uses throwaway keys generated on the fly. It is a demo and a test fixture
generator, not a production issuer. The payload is deliberately shaped like a
minimal eval claim to hint at the v0.3 eval-receipt vision, but the verifier
treats it as opaque bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# Allow running from the repo root without installing.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from proofbundle import merkle  # noqa: E402


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_sd_jwt(issuer: Ed25519PrivateKey) -> tuple[str, bytes]:
    """Build a tiny EdDSA SD-JWT with two selectively disclosable claims."""
    disclosures = []
    committed = []
    for salt, name, value in [
        ("c2FsdC1vbmU", "suite", "safety-refusal-v1"),
        ("c2FsdC10d28", "passed", True),
    ]:
        disc_json = json.dumps([salt, name, value], separators=(",", ":"))
        disc_b64 = b64url(disc_json.encode("utf-8"))
        digest = b64url(hashlib.sha256(disc_b64.encode("ascii")).digest())
        disclosures.append(disc_b64)
        committed.append(digest)

    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    payload = {
        "iss": "https://b7n0de.example",
        "vct": "https://b7n0de.example/eval-receipt",
        "iat": 1_760_000_000,
        "_sd_alg": "sha-256",
        "_sd": committed,
    }
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = issuer.sign(signing_input)
    jwt = f"{header_b64}.{payload_b64}.{b64url(sig)}"
    compact = "~".join([jwt] + disclosures) + "~"
    return compact, raw_pub(issuer)


def build_bundle() -> dict:
    signer = Ed25519PrivateKey.generate()
    issuer = Ed25519PrivateKey.generate()

    claim = {
        "suite": "safety-refusal-v1",
        "metric": "refusal_rate",
        "threshold": 0.8,
        "passed": True,
        "ci95": [0.83, 0.90],
        "prereg_sha256": hashlib.sha256(b"preregistration-protocol-v1").hexdigest(),
    }
    payload = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signer.sign(payload)

    # Anchor the payload as one leaf of a small RFC 6962 Merkle tree.
    leaves = [
        b"prior-evidence-0",
        payload,
        b"prior-evidence-2",
        b"prior-evidence-3",
    ]
    index = 1
    root = merkle.merkle_tree_hash(leaves)
    proof = merkle.inclusion_proof(leaves, index)

    sd_compact, issuer_pub = make_sd_jwt(issuer)

    bundle = {
        "schema": "proofbundle/v0.1",
        "payload_b64": b64(payload),
        "signature": {
            "alg": "ed25519",
            "public_key_b64": b64(raw_pub(signer)),
            "sig_b64": b64(signature),
        },
        "merkle": {
            "hash_alg": "sha256-rfc6962",
            "leaf_index": index,
            "tree_size": len(leaves),
            "inclusion_proof_b64": [b64(p) for p in proof],
            "root_b64": b64(root),
        },
        "sd_jwt_vc": {
            "compact": sd_compact,
            "issuer_public_key_b64": b64(issuer_pub),
        },
    }
    return bundle


def main() -> None:
    bundle = build_bundle()
    out = os.path.join(os.path.dirname(__file__), "example_bundle.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
