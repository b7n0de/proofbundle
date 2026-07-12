"""Generic external time-anchor layer for proofbundle receipts (EXPERIMENTAL; `[anchors]` extra).

An **anchor** is external evidence that a target existed at (or before) a time — something the receipt's
own Ed25519 + Merkle structure cannot establish on its own, because a self-emitted timestamp is only
producer-clock testimony. Three targets, **never mixed**:

* ``preRegistration`` — "the commitment existed BEFORE the run" (backdating protection; the point raised
  in in-toto/attestation#565).
* ``receipt`` — "the receipt existed from time T" (publication proof).
* ``statement`` — "this in-toto Statement's content existed from time T": the content root of a DSSE
  Statement (used by decision receipts). Anchor evidence for a statement's OWN content root is kept
  DETACHED (outside the signed bytes) — an anchor cannot live inside the bytes whose hash it commits
  without subset canonicalization, which is forbidden (proofbundle#7 consensus, 2026-07-10).

Each ``anchors[]`` entry is ``{type, target, canonicalRoot, proof, anchoredAt}``:

* ``type`` — ``rfc3161-tsa`` | ``opentimestamps`` | ``<extension>/vN``.
* ``target`` — ``receipt`` | ``preRegistration`` | ``statement`` (see above).
* ``canonicalRoot`` — base64 of the canonical root of the target: for ``receipt`` the RFC 8785 (JCS)
  sha256 of the receipt bundle; for ``preRegistration`` the sha256 of the raw protocol bytes (the
  receipt's ``prereg_sha256``); for ``statement`` the sha256 of the exact DSSE payload bytes
  (``statement_content_root``). The anchor timestamps THIS root.
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

ANCHOR_TARGETS = ("receipt", "preRegistration", "statement")
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


def statement_content_root(payload_bytes: bytes) -> bytes:
    """The content root a ``statement`` anchor stamps: SHA-256 over the EXACT DSSE payload bytes of an
    in-toto Statement (for a decision receipt, the RFC 8785 canonical statement bytes as signed).

    Deliberately hashes the exact transmitted bytes — the verifier NEVER re-canonicalizes (DSSE rule).
    The content root binds the CLAIM CONTENT, never the signature bytes, so it survives counter-signing,
    key rotation and multi-signature envelopes (b7n0de/proofbundle#7 consensus, 2026-07-10). The caller
    (verify_decision_receipt) has already fail-closed if the payload deviates from its own RFC 8785 form.

    Thin wrapper over the shared ``canonical.statement_content_root`` primitive (ADR 0002) so this anchor
    entry point and decision.py resolve the content root from ONE definition; the type-check stays here to
    keep the anchor-layer ``BundleFormatError`` contract (a non-bytes target is a fail-closed schema error,
    not a producer-side canonicalization)."""
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise BundleFormatError("statement content root needs the raw payload bytes")
    from . import canonical  # noqa: PLC0415
    return canonical.statement_content_root(bytes(payload_bytes))


def _call_verifier(fn: Callable, proof: bytes, canonical_root: bytes, *,
                   frozen: dict, now: Optional[int], rp_trust: Optional[dict]) -> dict:
    """Dispatch to an anchor verifier, backward-compatibly. WP-A1 added the ``rp_trust`` kwarg (relying-
    party trust material); a third-party verifier registered before A-1 accepts only ``(proof, root, *,
    frozen, now)``. Pass ``rp_trust`` only when the verifier's signature accepts it (or takes ``**kwargs``),
    so pre-A1 extension verifiers keep working — they simply never see RP trust (their own trust model)."""
    import inspect  # noqa: PLC0415
    kw: dict = {"frozen": frozen, "now": now}
    try:
        params = inspect.signature(fn).parameters
        if "rp_trust" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            kw["rp_trust"] = rp_trust
    except (ValueError, TypeError):   # a builtin/C callable with no introspectable signature
        pass
    return fn(proof, canonical_root, **kw)


def verify_anchor(anchor: dict, *, target_roots: dict, now: Optional[int] = None,
                  rp_trust: Optional[dict] = None) -> dict:
    """Verify ONE anchor entry, fail-closed. ``target_roots`` maps a target name to its canonical root
    bytes (only the targets that exist for this receipt). ``rp_trust`` (WP-A1) is the relying-party trust
    material (TSA roots, Bitcoin block headers) — the ONLY source of trust for a confirmed time anchor;
    the bundle's own ``frozen`` block is evidence, never trust. Returns ``{ok, type, target, detail}``."""
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
    anchored_at = anchor.get("anchoredAt")
    if anchored_at is not None and not isinstance(anchored_at, str):
        # WP-A7: anchoredAt is INFORMATIVE, but a non-string value is malformed input, not a
        # display nicety — fail closed like every other schema violation (detached anchors have no
        # JSON-schema layer in front of them).
        out["detail"] = "anchor anchoredAt must be an RFC 3339 string or null (informative only)"
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
        res = _call_verifier(_VERIFIERS[atype], proof, canonical_root,
                             frozen=anchor.get("frozen") or {}, now=now, rp_trust=rp_trust)
    except Exception as exc:   # a verifier must be fail-closed; if it raises, treat as FAIL, never pass
        out["detail"] = f"anchor verifier error (fail-closed): {exc}"
        return out
    out["ok"] = bool(res.get("ok"))
    out["warn"] = bool(res.get("warn"))
    out["status"] = res.get("status") or ("pass" if out["ok"] else ("warn" if out["warn"] else "fail"))
    out["detail"] = res.get("detail", "")
    # WP-A1: surface the trust provenance so the relying party can see WHY (and the require gate can only
    # count RP-trusted anchors). `rp_trusted` True → verified against RP-supplied trust material;
    # `needs_rp_trust` True → the proof exists but confirming it needs RP material (frozen is not trust);
    # `frozenEvidence` True → the bundle carried frozen material, reported but never trusted.
    for _f in ("rp_trusted", "needs_rp_trust", "frozenEvidence"):
        if _f in res:
            out[_f] = bool(res.get(_f))
    # WP-A2: structured trusted time, carried VERBATIM from the type verifier — present only when
    # the proof genuinely carries it (rfc3161 gen_time; a confirmed Bitcoin height). NEVER guessed,
    # NEVER derived from the informative anchoredAt field.
    tt = res.get("trustedTime")
    if isinstance(tt, dict) and tt.get("source"):
        out["trustedTime"] = tt
    return out


def verify_anchors(anchors, *, target_roots: dict, require: Optional[str] = None,
                   require_target: Optional[str] = None,
                   allow_pending: bool = False, now: Optional[int] = None,
                   rp_trust: Optional[dict] = None) -> dict:
    """Verify a receipt's ``anchors``. Missing/empty → SKIP (unless ``require`` is set → FAIL). Present →
    fail-closed PASS/FAIL over every entry. ``require`` is ``None`` | ``'any'`` | a type string; when set,
    at least one anchor of that type (or any) must verify. Returns ``{status, detail, results}`` with
    ``status`` in {PASS, FAIL, WARN, SKIP}; when ``require`` is set the return ALSO carries
    ``require_met`` (bool) — the requirement verdict, kept SEPARATE from the aggregate ``status``.

    ``status`` is the INFORMATIVE aggregate over EVERY entry (a broken/unknown/unbound anchor makes it
    FAIL, never silent). ``require_met`` is the relying-party gate the CLI maps to the exit code: it is
    True iff at least one anchor of the required type actually verifies (``matched`` below). The two are
    deliberately distinct — an UNRELATED broken anchor must NOT fail a requirement that a DIFFERENT
    anchor satisfies, exactly as anchors are advisory-only when no requirement is set. So a receipt with
    a verifying required anchor AND an unrelated broken one reports ``require_met=True`` (→ exit 0) while
    ``status`` stays FAIL (the broken anchor is still surfaced). Basing the gate on the global ``status``
    was the WP4 aggregation bug this fixes.

    ``allow_pending`` (default ``False``) only changes what SATISFIES a ``require``: normally a
    PENDING/WARN anchor (e.g. an un-upgraded OpenTimestamps proof, or a level-i chia anchor) does NOT
    count as a verifying anchor, so ``--require-anchor`` demands a full external-time proof. With
    ``allow_pending=True`` (CLI ``--require-anchor … --allow-pending``) a pending anchor also satisfies
    the requirement — weaker, and the relying party opted into it explicitly. It never turns a broken
    anchor into a pass: a hard-failing anchor still aggregates to FAIL."""
    if require_target is not None and require_target not in ANCHOR_TARGETS:
        raise BundleFormatError(
            f"require_target must be one of {ANCHOR_TARGETS}, got {require_target!r}")
    if require_target is not None and not require:
        require = "any"   # a target requirement IS an anchor requirement (mirrors --anchor-type)
    if not anchors:
        if require:
            return {"status": "FAIL", "require_met": False,
                    "detail": f"--require-anchor {require} set but the receipt has no anchors",
                    "results": []}
        return {"status": "SKIP", "detail": "no external time anchors present", "results": []}
    if not isinstance(anchors, list):
        raise BundleFormatError("anchors must be a list")
    results = [verify_anchor(a, target_roots=target_roots, now=now, rp_trust=rp_trust) for a in anchors]
    if require:   # a warn/pending/inclusion-only anchor never SATISFIES a requirement — only a full one
        want = None if require == "any" else require
        # WP-A1: matched = ok ∧ ¬warn ∧ type ∧ TARGET. Matching the type alone was a backdating
        # hole: a relying party demanding pre-registration evidence (--anchor-target
        # preRegistration) was satisfied by a RECEIPT anchor stamped today — existence-now proves
        # nothing about existence-before-the-run.
        def _target_ok(r):
            return require_target is None or r["target"] == require_target
        if allow_pending:
            matched = [r for r in results
                       if (r["ok"] or r["warn"]) and (want is None or r["type"] == want)
                       and _target_ok(r)]
        else:
            matched = [r for r in results
                       if r["ok"] and not r["warn"] and (want is None or r["type"] == want)
                       and _target_ok(r)]
        if not matched:
            tgt = f" with target {require_target!r}" if require_target is not None else ""
            detail = (f"--require-anchor {require}{tgt} (--allow-pending): no verifying or pending anchor of that type/target"
                      if allow_pending else
                      f"--require-anchor {require}{tgt}: no verifying anchor of that type/target")
            return {"status": "FAIL", "require_met": False, "detail": detail, "results": results}
    hard_fail = any(not r["ok"] and not r["warn"] for r in results)
    if hard_fail:
        status = "FAIL"                       # a broken/unbound/unknown anchor is never silent
    elif any(r["warn"] for r in results):
        status = "WARN"                       # e.g. a PENDING OpenTimestamps proof — not a full anchor yet
    else:
        status = "PASS"
    detail = f"{sum(r['ok'] for r in results)}/{len(results)} anchor(s) verified"
    out: dict = {"status": status, "detail": detail, "results": results}
    if require:   # reached here → `matched` is non-empty → the requirement IS met, regardless of an
        out["require_met"] = True   # UNRELATED anchor hard-failing (that stays advisory in `status`)
    return out
