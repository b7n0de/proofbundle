"""proofbundle — emit and verify portable, offline cryptographic evidence bundles for AI eval receipts.

Verify, fully offline and in pure Python, that a payload was Ed25519 signed and anchored under an RFC 6962
Merkle root, with optional SD-JWT selective disclosure — plus opt-in framework integrations that auto-emit a
signed receipt of an inspect_ai eval or a pytest run.

The public API is loaded LAZILY (PEP 562): ``import proofbundle`` — and, via the entry points, loading the
pytest plugin / inspect_ai hook — does NOT pull the crypto core until a name like ``verify_bundle`` is
actually used. ``from proofbundle import verify_bundle`` works exactly as before; it just imports the backing
module on first access. This keeps the framework integrations light at startup.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "2.0.0b1"

__all__ = [
    "__version__",
    "SCHEMA",
    "verify_bundle",
    "load_bundle",
    "recompute_merkle_root_b64",
    "emit_bundle",
    "generate_signer",
    "verify_inclusion",
    "verify_consistency",
    "verify_key_binding",
    "verify_tlog_proof",
    "verify_cosignature",
    "verify_witnessed_checkpoint",
    "verify_status_snapshot",
    "receipt_token",
    "verify_receipt_token",
    "build_sample_tree",
    "sample_opening",
    "verify_sample_opening",
    "audit_challenge",
    "prereg_hash",
    "verify_prereg",
    "beacon_audit_challenge",
    "VerificationResult",
    "Check",
    "ProofBundleError",
]

# name → backing submodule (relative). Loaded on first attribute access.
_LAZY = {
    "SCHEMA": ".bundle", "load_bundle": ".bundle", "verify_bundle": ".bundle",
    "recompute_merkle_root_b64": ".bundle",
    "emit_bundle": ".emit", "generate_signer": ".emit",
    "Check": ".errors", "ProofBundleError": ".errors", "VerificationResult": ".errors",
    "verify_consistency": ".merkle", "verify_inclusion": ".merkle",
    "verify_key_binding": ".kbjwt",
    "verify_tlog_proof": ".tlogproof",
    "verify_cosignature": ".checkpoint",
    "verify_witnessed_checkpoint": ".checkpoint",
    "verify_status_snapshot": ".statuslist",
    "receipt_token": ".hf_evals",
    "verify_receipt_token": ".hf_evals",
    "build_sample_tree": ".persample",
    "sample_opening": ".persample",
    "verify_sample_opening": ".persample",
    "audit_challenge": ".persample",
    "prereg_hash": ".prereg",
    "verify_prereg": ".prereg",
    "beacon_audit_challenge": ".beacon",
}

if TYPE_CHECKING:  # static analysers + IDEs see the real names/types; runtime stays lazy
    from .bundle import SCHEMA, load_bundle, recompute_merkle_root_b64, verify_bundle
    from .emit import emit_bundle, generate_signer
    from .errors import Check, ProofBundleError, VerificationResult
    from .checkpoint import verify_cosignature, verify_witnessed_checkpoint
    from .kbjwt import verify_key_binding
    from .hf_evals import receipt_token, verify_receipt_token
    from .persample import (audit_challenge, build_sample_tree, sample_opening,
                            verify_sample_opening)
    from .beacon import beacon_audit_challenge
    from .prereg import prereg_hash, verify_prereg
    from .statuslist import verify_status_snapshot
    from .tlogproof import verify_tlog_proof
    from .merkle import verify_consistency, verify_inclusion


def __getattr__(name: str):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib  # noqa: PLC0415
    return getattr(importlib.import_module(module, __name__), name)


def __dir__():
    return sorted(__all__)
