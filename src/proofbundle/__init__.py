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

__version__ = "3.2.2"

# The `proofbundle/v0.1` normative spec revision this build implements — kept in sync with the
# `Revision:` line at the top of SPEC.md by tests/test_docs_truth.py (WP-B1, closes #28). Bump
# both together whenever SPEC.md's normative text changes (not on every package release).
SPEC_REVISION = "2026-07-13"

__all__ = [
    "__version__",
    "SPEC_REVISION",
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
    "evaluation_card_hash",
    "verify_evaluation_card",
    "beacon_audit_challenge",
    "canonicalize_statement",
    "statement_content_root",
    "resolve_hash_alg",
    "compute_dual_hash",
    "verify_dual_hash",
    "build_evidence_pack",
    "verify_evidence_pack",
    "ots_upgraded_proof_is_self_contained",
    "build_initial_sequence",
    "renew_timestamp",
    "renew_hashtree",
    "verify_sequence",
    "last_ats",
    "evaluate_renewal_policy",
    "ArchiveTimeStamp",
    "RenewalPolicy",
    "verify_mldsa",
    "verify_slhdsa",
    "verify_hybrid",
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
    "evaluation_card_hash": ".evalcard",
    "verify_evaluation_card": ".evalcard",
    "beacon_audit_challenge": ".beacon",
    "canonicalize_statement": ".canonical",
    "statement_content_root": ".canonical",
    "resolve_hash_alg": ".hashalg",
    "compute_dual_hash": ".hashalg",
    "verify_dual_hash": ".hashalg",
    "build_evidence_pack": ".evidence_pack",
    "verify_evidence_pack": ".evidence_pack",
    "ots_upgraded_proof_is_self_contained": ".evidence_pack",
    "build_initial_sequence": ".renewal",
    "renew_timestamp": ".renewal",
    "renew_hashtree": ".renewal",
    "verify_sequence": ".renewal",
    "last_ats": ".renewal",
    "evaluate_renewal_policy": ".renewal",
    "ArchiveTimeStamp": ".renewal",
    "RenewalPolicy": ".renewal",
    "verify_mldsa": ".pqsig",
    "verify_slhdsa": ".pqsig",
    "verify_hybrid": ".pqsig",
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
    from .canonical import canonicalize_statement, statement_content_root
    from .hashalg import compute_dual_hash, resolve_hash_alg, verify_dual_hash
    from .evidence_pack import (build_evidence_pack, ots_upgraded_proof_is_self_contained,
                                verify_evidence_pack)
    from .renewal import (ArchiveTimeStamp, RenewalPolicy, build_initial_sequence,
                          evaluate_renewal_policy, last_ats, renew_hashtree, renew_timestamp,
                          verify_sequence)
    from .pqsig import verify_hybrid, verify_mldsa, verify_slhdsa
    from .prereg import prereg_hash, verify_prereg
    from .evalcard import evaluation_card_hash, verify_evaluation_card
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
