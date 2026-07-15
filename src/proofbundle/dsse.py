"""DSSE (Dead Simple Signing Envelope) v1 over Ed25519 — for the in-toto test-result export (v0.9).

Spec verified 2026-07 against secure-systems-lab/dsse (protocol.md, envelope.md) and in-toto/attestation
(spec/v1/envelope.md). The one thing that must be exact:

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

where SP is a single ASCII space (0x20), LEN(s) is the ASCII decimal BYTE length of s with no leading
zeros, `type` is the UTF-8 bytes of payloadType, and `body` is the RAW serialized payload bytes. The
signature is computed over PAE(payloadType, RAW body) — **never over the base64 string** (the classic DSSE
trap). Only the envelope's `payload` and each `signatures[].sig` are base64 (standard RFC 4648 §4, with
padding, NOT base64url); `payloadType` and `keyid` are plaintext.

Verification decodes `payload` and reconstructs PAE over the exact decoded bytes — it never re-serializes
or re-canonicalizes the JSON (that would change bytes and break the signature). We never roll our own
crypto: signing is `cryptography`'s Ed25519, verification is `proofbundle.signature.verify_ed25519`.

Base64 note: the envelope's `payload` and each `signatures[].sig` are base64. We EMIT standard RFC 4648 §4
(with padding), but the DSSE spec says a signer MAY use either standard or url-safe base64 and a verifier
MUST accept either — so verification accepts both alphabets. (This is distinct from the C2SP checkpoint,
which mandates standard base64.) The "classic DSSE trap" is a different thing: the SIGNATURE is over the
raw PAE body, never over the base64 string.
"""
from __future__ import annotations

import base64
import binascii
from typing import Optional

from .errors import BundleFormatError
from .signature import verify_ed25519

__all__ = ["pae", "sign_envelope", "verify_envelope"]


def _b64decode_any(s: str) -> bytes:
    """Decode standard OR url-safe base64 (DSSE verifiers MUST accept either). Tries standard first, then
    url-safe; raises binascii.Error if neither is valid."""
    try:
        return base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSEv1 Pre-Authentication Encoding. Signed/verified over the RAW body bytes, never base64."""
    t = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" "
            + str(len(body)).encode("ascii") + b" " + body)


def sign_envelope(body: bytes, signer, *, payload_type: str, keyid: Optional[str] = None) -> dict:
    """Sign the RAW `body` bytes into a DSSE envelope. `signer` is an Ed25519 private key (its `.sign`
    signs PAE(payload_type, body)). Returns {payload, payloadType, signatures:[{sig[, keyid]}]}."""
    sig = signer.sign(pae(payload_type, body))
    entry = {"sig": base64.b64encode(sig).decode("ascii")}
    if keyid:
        entry = {"keyid": keyid, "sig": entry["sig"]}
    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [entry],
    }


def _payload_bytes(envelope: dict) -> bytes:
    if not isinstance(envelope, dict):
        raise BundleFormatError("DSSE envelope must be a JSON object")
    p = envelope.get("payload")
    if not isinstance(p, str):
        raise BundleFormatError("DSSE envelope.payload must be a base64 string")
    try:
        return _b64decode_any(p)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise BundleFormatError("DSSE envelope.payload is not valid base64") from exc


def verify_envelope(envelope: dict, public_key: bytes, *, payload_type: Optional[str] = None) -> bool:
    """Verify a DSSE envelope against `public_key` (32 raw Ed25519 bytes). Decodes `payload` and rebuilds
    PAE over exactly those bytes (never re-serialized). True iff at least one signature verifies. If
    `payload_type` is given it MUST equal the envelope's payloadType (pin the type — a Sign/Verify type
    mismatch silently changes the PAE and would otherwise reject a genuine envelope for the wrong reason)."""
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import matches repo convention, avoids any cycle
    body = _payload_bytes(envelope)
    ptype = envelope.get("payloadType")
    if not isinstance(ptype, str) or not ptype:
        raise BundleFormatError("DSSE envelope.payloadType must be a non-empty string")
    if payload_type is not None and ptype != payload_type:
        return False
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise BundleFormatError("DSSE envelope.signatures must be a non-empty list")
    # Finding 15b DoS backstop (crypto-review, 2026-07-15): cap the attacker-controlled signatures list
    # BEFORE the verify loop. Without this, a tiny payload + a million-entry signatures list drives ~O(n)
    # Ed25519 verifies (no early exit, since none verify) = seconds of CPU per request — the input_bytes cap
    # bounds only the decoded payload, not this list. This is the single chokepoint every DSSE verify_*
    # entry point (decision/outcome/verification_summary/run_ledger) funnels through; trust_pack keeps its
    # own equivalent cap before its separate threshold loop. BudgetExceeded is a ProofBundleError subclass,
    # so existing except(ProofBundleError) sites already treat it as fail-closed malformed/over-limit input.
    DEFAULT_BUDGET.check("signatures", len(sigs))
    msg = pae(ptype, body)
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("sig")
        if not isinstance(raw, str):
            continue
        try:
            sig = _b64decode_any(raw)
        except (ValueError, TypeError, binascii.Error):
            continue
        if verify_ed25519(public_key, sig, msg):
            return True
    return False


def load_payload(envelope: dict) -> bytes:
    """Return the raw decoded payload bytes (the in-toto Statement JSON) — for a verified envelope."""
    return _payload_bytes(envelope)
