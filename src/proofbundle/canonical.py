"""Canonical Statement primitive — the one home for the universal content root (ADR 0002).

The *content root* of an in-toto Statement is ``SHA-256`` over the RFC-8785 (JCS) canonical bytes of the
**full** Statement (``_type``, ``subject``, ``predicateType``, ``predicate`` — never a predicate-only or
field-subset canonicalization) taken BEFORE signing. The signature bytes are NEVER part of the preimage, so
the root survives counter-signing, key rotation and multi-signature envelopes (proofbundle#7 consensus,
2026-07-10). ``contentRootAlg`` for this definition is ``jcs-sha256-v1`` (see ``CONTENT_ROOT_ALG``).

Two-part rule (ADR 0002):

* a PRODUCER emits its Statement canonically (``canonicalize_statement``) and signs exactly those bytes;
* a VERIFIER hashes the EXACT transmitted payload bytes and NEVER re-canonicalizes — a payload that deviates
  from its own canonical form is a fail-closed error the caller must reject.

``statement_content_root`` serves both sides from one definition: given a JSON object it canonicalizes then
hashes (producer); given raw ``bytes`` it hashes exactly those bytes (verifier). Both yield the SAME 32-byte
root when the producer emitted canonically — which is the whole point of a content root: a verifier that
passes the exact signed payload bytes reproduces the producer's root without trusting a re-serialization.

The RFC-8785 canonicalizer ships in the ``[eval]`` extra (``rfc8785``); it is imported LAZILY so the base
install and the plain no-anchor verify path stay dependency-free. A missing extra is a clear fail-closed
``CanonicalizerUnavailable``, never a raw ``ImportError``.

This module is intentionally tiny and dependency-light: it is the shared primitive that the decision-receipt
predicate (``decision.py``) and, across the 2.1.0 migration (ADR 0002), the eval-result / svr in-toto export
paths converge on. Providing it here does NOT change any released wire format — the migration of the released
``intoto`` export paths off ``json.dumps(sort_keys=True)`` is a separate T3 / SemVer owner-gated step.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Union

from .errors import ProofBundleError

__all__ = ["CONTENT_ROOT_ALG", "STATEMENT_REQUIRED_KEYS", "CanonicalizerUnavailable",
           "canonicalize_statement", "statement_content_root"]

# The declared content-root algorithm this primitive computes (ADR 0002): SHA-256 over the RFC-8785 (JCS)
# canonical Statement bytes. A future algorithm MUST register its own distinct id — a verifier MUST NOT
# silently default a missing/unknown value, which is exactly where an algorithm-confusion attack would hide.
CONTENT_ROOT_ALG = "jcs-sha256-v1"

# The four keys of a full in-toto Statement v1. Passing a bare `predicate` where a full Statement is
# required would drop `subject` + `predicateType` and reopen the §2.1 context-confusion attack at the
# primitive level (ADR 0002 §2, full-Statement scope) — the opt-in `require_statement_shape` guard below
# fails closed on that. NOT enforced by default: some callers legitimately canonicalize a bare predicate
# for a subject-commitment digest (e.g. decision.build_decision_statement), which is a different operation.
STATEMENT_REQUIRED_KEYS = ("_type", "subject", "predicateType", "predicate")


class CanonicalizerUnavailable(ProofBundleError):
    """The RFC 8785 (JCS) canonicalizer extra is not installed, so a content root cannot be computed.

    Fail-closed: install ``proofbundle[eval]``. Callers that want a predicate-specific message (e.g.
    ``decision.py``'s ``DecisionReceiptError``) catch this and re-raise."""


def _require_statement_shape(obj: Any) -> None:
    """Fail closed unless ``obj`` is a full in-toto Statement OBJECT (the four ``STATEMENT_REQUIRED_KEYS``).

    Guards the §2.1 bug class at the primitive level: handing a bare ``predicate`` to a routine that expects
    a full Statement silently narrows the content-root scope (``subject`` + ``predicateType`` dropped). This
    is opt-in (``require_statement_shape=True``) precisely because a bare-predicate canonicalization is a
    legitimate, distinct operation elsewhere; enabling it by default would break those callers."""
    if not isinstance(obj, Mapping):
        raise ProofBundleError(
            "require_statement_shape: a full in-toto Statement (JSON object) is required, got "
            f"{type(obj).__name__}")
    missing = [k for k in STATEMENT_REQUIRED_KEYS if k not in obj]
    if missing:
        raise ProofBundleError(
            f"require_statement_shape: object is missing in-toto Statement key(s) {missing} — this looks "
            "like a bare predicate, not a full Statement (subject + predicateType would be dropped; "
            "ADR 0002 §2 full-Statement scope)")


def canonicalize_statement(statement: Any, *, require_statement_shape: bool = False) -> bytes:
    """RFC-8785 (JCS) canonical bytes of a JSON in-toto Statement (or predicate) OBJECT.

    This is the producer-side canonicalization: the exact bytes to sign. It normalizes key order, number
    formatting and string escaping per RFC 8785, so two structurally-equal objects with different key
    insertion order produce byte-identical output. It does NOT hash and does NOT touch signatures.

    Uses the real ``rfc8785`` canonicalizer (the ``[eval]`` extra), lazily imported; a missing extra is a
    fail-closed ``CanonicalizerUnavailable``. Value errors from a non-JCS-able object (e.g. an unsafe float)
    propagate unchanged, exactly as calling ``rfc8785.dumps`` directly would.

    ``require_statement_shape=True`` (opt-in, default OFF) fails closed with ``ProofBundleError`` when
    ``statement`` is not a full in-toto Statement (the four ``STATEMENT_REQUIRED_KEYS``) — a guard against
    accidentally passing a bare ``predicate`` where the full-Statement scope is required (ADR 0002 §2). It is
    OFF by default because a bare-predicate canonicalization is a legitimate distinct operation (e.g. a
    subject-commitment digest); turning the check on by default would break those callers."""
    if require_statement_shape:
        _require_statement_shape(statement)
    try:
        import rfc8785  # noqa: PLC0415 — lazy: only the canonical/emit path pulls the JCS dependency
    except ImportError as exc:
        raise CanonicalizerUnavailable(
            "computing a Statement content root needs the RFC 8785 (JCS) canonicalizer — "
            "install proofbundle[eval]") from exc
    return rfc8785.dumps(statement)


def statement_content_root(statement: Union[Mapping, list, bytes, bytearray], *,
                           require_statement_shape: bool = False) -> bytes:
    """The content root of a Statement: 32 raw SHA-256 bytes over its canonical Statement bytes (ADR 0002).

    Accepts either side of the two-part rule:

    * a JSON OBJECT (``Mapping`` / ``list``) — the PRODUCER path: canonicalize (RFC 8785) then SHA-256;
    * raw ``bytes`` — the VERIFIER path: SHA-256 over the EXACT payload bytes, NEVER re-canonicalized.

    Both return the SAME root when the producer emitted canonically, so a verifier that passes the exact
    signed payload bytes reproduces the producer's root without trusting a re-serialization. The preimage is
    the STATEMENT (pre-signature); signature/envelope bytes are never included, so the root is stable across
    counter-signing, key rotation and multi-signature envelopes.

    ``.hex()`` on the return value gives the 64-char hex digest used in ``evidenceRefs[].digest.sha256`` and
    a ``statement`` anchor's ``canonicalRoot``.

    ``require_statement_shape=True`` (opt-in, default OFF) guards the OBJECT (producer) path against a bare
    predicate (see ``canonicalize_statement``). It does NOT apply to the ``bytes`` (verifier) path — opaque
    transmitted bytes cannot be introspected, and their shape was fixed at produce time."""
    if isinstance(statement, (bytes, bytearray)):
        # Verifier path: hash the exact transmitted payload bytes; do NOT re-canonicalize (DSSE rule). The
        # shape guard is not applicable to opaque bytes (documented) — the caller checked shape at produce.
        return hashlib.sha256(bytes(statement)).digest()
    if isinstance(statement, (Mapping, list)):
        # Producer path: canonicalize the object (optionally shape-guarded), then hash.
        return hashlib.sha256(
            canonicalize_statement(statement, require_statement_shape=require_statement_shape)).digest()
    raise ProofBundleError(
        "statement_content_root needs a JSON object (dict/list) to canonicalize or the exact payload "
        f"bytes; got {type(statement).__name__}")
