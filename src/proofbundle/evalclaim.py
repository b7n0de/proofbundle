"""Eval receipts (v0.4): sign + Merkle-anchor a canonical eval CLAIM.

A receipt proves exactly one thing — *suite S scored `comparator` threshold T,
passed=…* — carrying only SALTED commitments to the model and dataset identifiers,
never the weights, the data, or the plaintext names. A third party verifies the
threshold was met, offline, from one file, without ever seeing the model or dataset.

Honest scope (see EVAL_CLAIM.md): the receipt proves `passed` against `threshold`
and hides the model/dataset via salted commitments. It does NOT prove the evaluation
itself was well designed or that the suite measures what it claims — those are human
judgements. What it removes is the need to simply *trust the number*.

Layering: the claim payload is canonicalized with RFC 8785 JCS **only on the emit
path** (a lazy dependency). The verify path (`decode_eval_claim`) never canonicalizes —
it checks the exact stored bytes that `verify_bundle` already authenticated — so the
verifier stays dependency-free (cryptography + stdlib only).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import unicodedata
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .bundle import load_bundle, verify_bundle
from .emit import emit_bundle

EVAL_CLAIM_SCHEMA = "proofbundle/eval-claim/v0.1"
COMMIT_ALG = "sha256-salted-v1"
_COMPARATORS = {">=", ">", "<=", "<"}
_MAX_SAFE_INT = 2 ** 53 - 1
# The exact key set of an eval claim; decode/validate reject anything else.
_REQUIRED = {"schema", "suite", "suite_version", "metric", "comparator", "threshold",
             "passed", "n", "model_id_commit", "dataset_id_commit", "commit_alg", "issuer", "timestamp"}
_OPTIONAL = {"context_binding", "ci95", "multiple_testing", "prereg_sha256"}

__all__ = [
    "EVAL_CLAIM_SCHEMA", "COMMIT_ALG", "canonicalize", "build_eval_claim",
    "emit_eval_receipt", "decode_eval_claim", "salted_commit", "issuer_fingerprint",
]


class EvalClaimError(ValueError):
    """Raised for a malformed eval claim (float in payload, non-NFC string, unsafe int, …)."""


def issuer_fingerprint(signer: Ed25519PrivateKey) -> str:
    """The `issuer` field value: ed25519:<base64 of the 32-byte raw public key>."""
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def salted_commit(identifier: str, salt: bytes) -> str:
    """Salted commitment to an identifier: sha256:<hex> over salt || utf8(identifier).

    The salt (>=16 bytes, high entropy) stays with the issuer and is NEVER in the payload,
    so the identifier cannot be recovered from the commitment — not even via a rainbow table
    over known model names like gpt-4o.
    """
    if len(salt) < 16:
        raise EvalClaimError("commitment salt must be at least 16 bytes")
    return "sha256:" + hashlib.sha256(salt + identifier.encode("utf-8")).hexdigest()


def _reject_non_jcs(value) -> None:
    """Recursively reject values that RFC 8785 / this profile forbids in a claim."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise EvalClaimError("float values are forbidden; use a decimal STRING (e.g. \"0.80\")")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise EvalClaimError(f"integer {value} exceeds the IEEE-754 safe range (2**53-1)")
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise EvalClaimError("string is not NFC-normalized")
        return
    if value is None:
        return
    if isinstance(value, dict):
        for v in value.values():
            _reject_non_jcs(v)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _reject_non_jcs(v)
        return
    raise EvalClaimError(f"unsupported value type {type(value).__name__}")


def canonicalize(claim: dict) -> bytes:
    """RFC 8785 JCS canonical bytes of a claim — EMIT PATH ONLY.

    Enforces the profile before serializing: no Python float, NFC strings, safe-range ints.
    Duplicate keys cannot exist in a Python dict; when parsing claim JSON from text, use
    `load_claim_text` which rejects duplicate keys. Uses the rfc8785 library (lazy import)
    for the UTF-16 code-unit key sort + compact UTF-8 serialization.
    """
    _reject_non_jcs(claim)
    import rfc8785  # noqa: PLC0415 — lazy: only the emit path pulls the JCS dependency
    try:
        return rfc8785.dumps(claim)
    except (rfc8785.FloatDomainError, rfc8785.IntegerDomainError, rfc8785.CanonicalizationError) as e:
        raise EvalClaimError(f"canonicalization failed: {e}") from e


def load_claim_text(text: str) -> dict:
    """Parse claim JSON text, rejecting duplicate keys (JCS forbids them)."""
    def _no_dupes(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                raise EvalClaimError(f"duplicate key {k!r} in claim JSON")
            seen[k] = v
        return seen
    return json.loads(text, object_pairs_hook=_no_dupes)


def build_eval_claim(*, suite: str, suite_version: str, metric: str, comparator: str,
                     threshold: str, score: str, n: int, model_id: str, dataset_id: str,
                     issuer: str, timestamp: str, context_binding: Optional[str] = None,
                     ci95: Optional[Sequence[str]] = None, multiple_testing: Optional[str] = None,
                     prereg_sha256: Optional[str] = None,
                     model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Build a valid eval claim from raw values. Computes `passed` ITSELF from the comparator
    (never trusts the caller), creates salted commitments, and returns (claim, salts) with the
    salts SEPARATE (never in the payload).

    threshold/score are decimal STRINGS (never floats). Returns:
        (claim: dict, salts: {"model_salt": bytes, "dataset_salt": bytes})
    """
    if comparator not in _COMPARATORS:
        raise EvalClaimError(f"comparator must be one of {sorted(_COMPARATORS)}")
    for name, val in (("threshold", threshold), ("score", score)):
        if not isinstance(val, str):
            raise EvalClaimError(f"{name} must be a decimal STRING, not {type(val).__name__}")
    from decimal import Decimal, InvalidOperation  # noqa: PLC0415
    try:
        s, t = Decimal(score), Decimal(threshold)
    except InvalidOperation as e:
        raise EvalClaimError(f"threshold/score are not valid decimals: {e}") from e
    passed = {">=": s >= t, ">": s > t, "<=": s <= t, "<": s < t}[comparator]
    m_salt = model_salt if model_salt is not None else os.urandom(16)
    d_salt = dataset_salt if dataset_salt is not None else os.urandom(16)
    claim = {
        "schema": EVAL_CLAIM_SCHEMA, "suite": suite, "suite_version": suite_version,
        "metric": metric, "comparator": comparator, "threshold": threshold, "passed": passed,
        "n": n, "model_id_commit": salted_commit(model_id, m_salt),
        "dataset_id_commit": salted_commit(dataset_id, d_salt), "commit_alg": COMMIT_ALG,
        "issuer": issuer, "timestamp": timestamp,
    }
    if context_binding is not None:
        claim["context_binding"] = context_binding
    if ci95 is not None:
        claim["ci95"] = [str(x) for x in ci95]
    if multiple_testing is not None:
        claim["multiple_testing"] = multiple_testing
    if prereg_sha256 is not None:
        claim["prereg_sha256"] = prereg_sha256
    _reject_non_jcs(claim)
    return claim, {"model_salt": m_salt, "dataset_salt": d_salt}


def emit_eval_receipt(claim: dict, signer: Ed25519PrivateKey, *, prior_leaves: Sequence[bytes] = (),
                      sd_jwt: Optional[dict] = None) -> dict:
    """Emit a proofbundle/v0.1 bundle whose payload is the canonical eval claim.

    Sets `issuer` to the signer's fingerprint automatically (binding the receipt to the key),
    canonicalizes, and calls emit_bundle. The returned bundle is verified unchanged by verify_bundle.
    """
    claim = dict(claim)
    claim["issuer"] = issuer_fingerprint(signer)
    missing = _REQUIRED - set(claim)
    if missing:
        raise EvalClaimError(f"claim missing required fields: {sorted(missing)}")
    extra = set(claim) - _REQUIRED - _OPTIONAL
    if extra:
        raise EvalClaimError(f"claim has unknown fields: {sorted(extra)}")
    payload = canonicalize(claim)
    return emit_bundle(payload, signer, prior_leaves=prior_leaves, sd_jwt_vc=sd_jwt)


def decode_eval_claim(bundle) -> Optional[dict]:
    """Verify the bundle, then check the signing key matches the claim's `issuer` field.

    Returns the parsed claim on success, None on any failure. Dependency-free (no JCS import):
    it re-reads the exact stored payload bytes that verify_bundle already authenticated.
    """
    result = verify_bundle(bundle)
    if not result.ok:
        return None
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)   # a str is a PATH (consistent with verify_bundle)
    try:
        payload = base64.b64decode(bundle["payload_b64"])
        claim = load_claim_text(payload.decode("utf-8"))
        if claim.get("schema") != EVAL_CLAIM_SCHEMA:
            return None
        # Issuer binding: the claim's issuer must be the key that signed the bundle.
        sig_pub_b64 = bundle["signature"]["public_key_b64"]
        want = "ed25519:" + base64.b64encode(base64.b64decode(sig_pub_b64)).decode("ascii")
        if claim.get("issuer") != want:
            return None
        return claim
    except (KeyError, ValueError, EvalClaimError):
        return None
