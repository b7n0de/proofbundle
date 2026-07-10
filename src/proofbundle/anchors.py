"""Generic external time-anchor layer for proofbundle receipts (EXPERIMENTAL; `[anchors]` extra).

An **anchor** is external evidence that a target existed at (or before) a time — something the receipt's
own Ed25519 + Merkle structure cannot establish on its own, because a self-emitted timestamp is only
producer-clock testimony. Two targets, **never mixed**:

* ``preRegistration`` — "the commitment existed BEFORE the run" (backdating protection; the point raised
  in in-toto/attestation#565).
* ``receipt`` — "the receipt existed from time T" (publication proof).

Each ``anchors[]`` entry is ``{type, target, canonicalRoot, proof, anchoredAt}``:

* ``type`` — ``rfc3161-tsa`` | ``opentimestamps`` | ``<extension>/vN``.
* ``target`` — ``receipt`` | ``preRegistration`` (see above).
* ``canonicalRoot`` — base64 of the canonical root of the target: for ``receipt`` the RFC 8785 (JCS)
  sha256 of the receipt bundle; for ``preRegistration`` the sha256 of the raw protocol bytes (the
  receipt's ``prereg_sha256``). The anchor timestamps THIS root.
* ``proof`` — base64 of the type-specific proof (an RFC 3161 token, an OpenTimestamps proof, ...).
* ``anchoredAt`` — RFC 3339 Z, INFORMATIVE only (the trusted time comes from the proof, not this field).

**Verify contract (fail-closed).** Missing/empty ``anchors`` → SKIP (never FAIL — consistent with
in-toto's Monotonic Principle: deny only when an attestation is present and wrong). Present → fail-closed:
a root mismatch, an unknown type, or a broken proof is a FAIL, never silent. ``require`` (CLI
``--require-anchor <type|any>``) turns "no verifying anchor" into a FAIL.

**Cross-target safety.** ``canonicalRoot`` is compared to the root of the anchor's OWN ``target`` — a
``preRegistration`` anchor can never validate a ``receipt`` target and vice versa (the roots differ).

**Lean core.** This module is pure dispatch + schema; the RFC 3161 / OpenTimestamps verifiers lazy-import
their libraries and are only needed with the ``[anchors]`` extra. The base install pulls only
``cryptography``; a bundle with no anchors verifies unchanged. Anchoring writes a NEW file — a network
error while stamping never corrupts the local receipt.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Callable, Optional

from .errors import BundleFormatError

ANCHOR_TARGETS = ("receipt", "preRegistration")
_ANCHOR_KEYS = {"type", "target", "canonicalRoot", "proof", "anchoredAt", "frozen"}

# type name -> verifier callable:
#   (proof: bytes, canonical_root: bytes, *, frozen: dict, now: Optional[int]) -> {"ok": bool, "detail": str}
_VERIFIERS: dict[str, Callable] = {}


def register_anchor_type(type_name: str, verifier: Callable) -> None:
    """Register a verifier for an anchor ``type``. A third party ships its own type this way (see
    docs/ANCHORS.md). The verifier MUST be fail-closed: return ``{"ok": False, ...}`` on any doubt,
    never raise for an ordinary bad proof."""
    if not type_name or not isinstance(type_name, str) or not callable(verifier):
        raise BundleFormatError("register_anchor_type needs a non-empty name and a callable verifier")
    _VERIFIERS[type_name] = verifier


def registered_anchor_types() -> tuple:
    _ensure_builtin_types()
    return tuple(sorted(_VERIFIERS))


def _ensure_builtin_types() -> None:
    """Lazily register the built-in anchor verifiers (rfc3161-tsa, opentimestamps). Each needs the
    ``[anchors]`` extra; if a library is absent the type stays UNREGISTERED — which the verify path
    treats as an unknown type → FAIL (fail-closed), exactly the behaviour we want without the extra."""
    if "rfc3161-tsa" not in _VERIFIERS:
        try:
            from . import anchors_rfc3161  # noqa: PLC0415
            _VERIFIERS["rfc3161-tsa"] = anchors_rfc3161.verify_rfc3161
        except Exception:   # extra missing / import failure → leave unregistered (fail-closed)
            pass
    if "opentimestamps" not in _VERIFIERS:
        try:
            from . import anchors_ots  # noqa: PLC0415
            _VERIFIERS["opentimestamps"] = anchors_ots.verify_opentimestamps
        except Exception:
            pass
    # chia-datalayer/v1: the first FIRST-PARTY extension anchor. Its offline Merkle verifier (level i) is
    # PURE SHA-256 — no Chia software, no extra — so it always registers (writing an anchor via anchor-add
    # needs the [chia] extra + a node, but VERIFYING one offline does not).
    if "chia-datalayer/v1" not in _VERIFIERS:
        try:
            from . import anchors_chia  # noqa: PLC0415
            _VERIFIERS[anchors_chia.ANCHOR_TYPE] = anchors_chia.verify_chia_datalayer
        except Exception:   # pragma: no cover - pure module, import should not fail
            pass


def _b64d(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise BundleFormatError(f"anchor {field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BundleFormatError(f"anchor {field} is not valid base64") from exc


def receipt_canonical_root(bundle: dict) -> bytes:
    """The RFC 8785 (JCS) sha256 of the receipt bundle — the canonical root a ``receipt`` anchor stamps.
    Uses a real RFC 8785 canonicalizer (the ``[anchors]``/``[eval]`` extra); never a home-grown sort."""
    try:
        import rfc8785  # noqa: PLC0415
    except ImportError as exc:   # pragma: no cover - guarded by the extra
        raise BundleFormatError(
            "receipt anchoring needs the RFC 8785 canonicalizer — install proofbundle[anchors]") from exc
    return hashlib.sha256(rfc8785.dumps(bundle)).digest()


def prereg_canonical_root(prereg_sha256_hex: str) -> bytes:
    """The canonical root a ``preRegistration`` anchor stamps: the sha256 (raw bytes) of the eval
    protocol file, i.e. the receipt's ``prereg_sha256``."""
    if not isinstance(prereg_sha256_hex, str) or len(prereg_sha256_hex) != 64:
        raise BundleFormatError("prereg canonical root needs a 64-char hex sha256")
    try:
        return bytes.fromhex(prereg_sha256_hex)
    except ValueError as exc:
        raise BundleFormatError("prereg_sha256 is not valid hex") from exc


def verify_anchor(anchor: dict, *, target_roots: dict, now: Optional[int] = None) -> dict:
    """Verify ONE anchor entry, fail-closed. ``target_roots`` maps a target name to its canonical root
    bytes (only the targets that exist for this receipt). Returns ``{ok, type, target, detail}``."""
    _ensure_builtin_types()
    if not isinstance(anchor, dict):
        raise BundleFormatError("each anchor must be a JSON object")
    unknown = set(anchor) - _ANCHOR_KEYS
    if unknown:
        raise BundleFormatError(f"anchor has unknown field(s) {sorted(unknown)}")
    atype = anchor.get("type")
    target = anchor.get("target")
    out = {"ok": False, "warn": False, "status": "fail", "type": atype, "target": target, "detail": ""}
    if target not in ANCHOR_TARGETS:
        out["detail"] = f"anchor target must be one of {ANCHOR_TARGETS}"
        return out
    if not isinstance(atype, str) or atype not in _VERIFIERS:
        # Unknown type is a FAIL, not a SKIP — an anchor we cannot check must never pass silently.
        out["detail"] = (f"no verifier registered for anchor type {atype!r} "
                         "(install proofbundle[anchors] or register the extension type)")
        return out
    expected_root = target_roots.get(target)
    if expected_root is None:
        out["detail"] = f"the receipt has no {target} target to anchor against"
        return out
    canonical_root = _b64d(anchor.get("canonicalRoot"), "canonicalRoot")
    if canonical_root != expected_root:
        # cross-target safety: a preRegistration anchor's root never equals the receipt root, and v.v.
        out["detail"] = f"canonicalRoot does not match the {target} root (cross-target or tampered)"
        return out
    proof = _b64d(anchor.get("proof"), "proof")
    try:
        res = _VERIFIERS[atype](proof, canonical_root, frozen=anchor.get("frozen") or {}, now=now)
    except Exception as exc:   # a verifier must be fail-closed; if it raises, treat as FAIL, never pass
        out["detail"] = f"anchor verifier error (fail-closed): {exc}"
        return out
    out["ok"] = bool(res.get("ok"))
    out["warn"] = bool(res.get("warn"))
    out["status"] = res.get("status") or ("pass" if out["ok"] else ("warn" if out["warn"] else "fail"))
    out["detail"] = res.get("detail", "")
    return out


def verify_anchors(anchors, *, target_roots: dict, require: Optional[str] = None,
                   allow_pending: bool = False, now: Optional[int] = None) -> dict:
    """Verify a receipt's ``anchors``. Missing/empty → SKIP (unless ``require`` is set → FAIL). Present →
    fail-closed PASS/FAIL over every entry. ``require`` is ``None`` | ``'any'`` | a type string; when set,
    at least one anchor of that type (or any) must verify. Returns ``{status, detail, results}`` with
    ``status`` in {PASS, FAIL, WARN, SKIP}.

    ``allow_pending`` (default ``False``) only changes what SATISFIES a ``require``: normally a
    PENDING/WARN anchor (e.g. an un-upgraded OpenTimestamps proof, or a level-i chia anchor) does NOT
    count as a verifying anchor, so ``--require-anchor`` demands a full external-time proof. With
    ``allow_pending=True`` (CLI ``--require-anchor … --allow-pending``) a pending anchor also satisfies
    the requirement — weaker, and the relying party opted into it explicitly. It never turns a broken
    anchor into a pass: a hard-failing anchor still aggregates to FAIL."""
    if not anchors:
        if require:
            return {"status": "FAIL", "detail": f"--require-anchor {require} set but the receipt has no anchors",
                    "results": []}
        return {"status": "SKIP", "detail": "no external time anchors present", "results": []}
    if not isinstance(anchors, list):
        raise BundleFormatError("anchors must be a list")
    results = [verify_anchor(a, target_roots=target_roots, now=now) for a in anchors]
    if require:   # a warn/pending/inclusion-only anchor never SATISFIES a requirement — only a full one
        want = None if require == "any" else require
        if allow_pending:
            matched = [r for r in results
                       if (r["ok"] or r["warn"]) and (want is None or r["type"] == want)]
        else:
            matched = [r for r in results
                       if r["ok"] and not r["warn"] and (want is None or r["type"] == want)]
        if not matched:
            detail = (f"--require-anchor {require} (--allow-pending): no verifying or pending anchor of that type"
                      if allow_pending else
                      f"--require-anchor {require}: no verifying anchor of that type")
            return {"status": "FAIL", "detail": detail, "results": results}
    hard_fail = any(not r["ok"] and not r["warn"] for r in results)
    if hard_fail:
        status = "FAIL"                       # a broken/unbound/unknown anchor is never silent
    elif any(r["warn"] for r in results):
        status = "WARN"                       # e.g. a PENDING OpenTimestamps proof — not a full anchor yet
    else:
        status = "PASS"
    detail = f"{sum(r['ok'] for r in results)}/{len(results)} anchor(s) verified"
    return {"status": status, "detail": detail, "results": results}
