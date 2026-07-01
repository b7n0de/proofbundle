"""proofbundle, an offline verifier for portable cryptographic evidence bundles.

Verify, fully offline and in pure Python, that a payload was Ed25519 signed and
anchored under an RFC 6962 Merkle root, with optional SD-JWT selective
disclosure. The verification half of a signed, third-party-verifiable evidence
receipt.
"""

from __future__ import annotations

from .bundle import SCHEMA, load_bundle, verify_bundle
from .emit import emit_bundle, generate_signer
from .errors import Check, ProofBundleError, VerificationResult
from .merkle import verify_consistency, verify_inclusion

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "SCHEMA",
    "verify_bundle",
    "load_bundle",
    "emit_bundle",
    "generate_signer",
    "verify_inclusion",
    "verify_consistency",
    "VerificationResult",
    "Check",
    "ProofBundleError",
]
