"""Token Status List snapshot verification — offline revocation for receipts (v1.3).

Implements the verify side of IETF **Token Status List** (draft-ietf-oauth-status-list, draft-21,
in the RFC-Editor queue 2026-06 — the wire format is frozen; spec verified 2026-07-02 against the
datatracker). A Status List Token (SLT) is a signed JWT (`typ: "statuslist+jwt"`) whose payload
carries `sub` (the list URI), `iat`, optional `exp`/`ttl`, and `status_list: {bits, lst}` where
`lst` is base64url(zlib(DEFLATE(bit-array))) and `bits` ∈ {1, 2, 4, 8} is the per-token status
width. A Referenced Token (e.g. a proofbundle SD-JWT receipt) points into the list via its
`status.status_list.{idx, uri}` claim.

**The offline model — a bundled snapshot, staleness made explicit.** proofbundle never fetches.
The relying party supplies the SLT (obtained/bundled at emit time or refreshed out of band) plus
the status issuer's key. The verifier checks the SLT signature (EdDSA, consistent with the rest of
proofbundle), the `typ`, the `sub`↔`uri` match, decodes the bit array, and reads the status at
`idx`. Freshness (`iat`/`exp`/`ttl`) is REPORTED, and only JUDGED when the caller passes `now` —
an offline verifier has no trusted clock, so time policy stays the relying party's, stated
honestly instead of silently assumed.

The bundle format `proofbundle/v0.1` is UNCHANGED: the snapshot is a separate input, never a new
bundle field (old verifiers reject unknown fields by design — that guarantee is kept).
"""

from __future__ import annotations

import base64
import json
import zlib
from typing import Optional

from .errors import BundleFormatError
from .signature import verify_ed25519

__all__ = ["STATUS_LABELS", "verify_status_snapshot", "status_claim", "issue_status_list_token"]

# Registered status values (draft-ietf-oauth-status-list §7): the rest of the 1-byte space is
# application-specific; anything unknown is reported by numeric value.
STATUS_LABELS = {0x00: "VALID", 0x01: "INVALID", 0x02: "SUSPENDED"}
_ALLOWED_BITS = (1, 2, 4, 8)
# Decompression-bomb cap for the zlib status-list bit array (CWE-409). 64 MiB holds ~536M single-bit entries —
# far beyond any realistic revocation list — while bounding a malicious tiny-input → huge-output expansion.
_MAX_STATUS_LIST_BYTES = 64 * 1024 * 1024
TYP = "statuslist+jwt"


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def status_claim(uri: str, idx: int) -> dict:
    """The `status` claim a Referenced Token (receipt SD-JWT) carries to point into a list."""
    if not uri or not isinstance(uri, str):
        raise BundleFormatError("status list uri must be a non-empty string")
    if isinstance(idx, bool) or not isinstance(idx, int) or idx < 0:
        raise BundleFormatError("status list index must be a non-negative integer")
    return {"status_list": {"idx": idx, "uri": uri}}


def _status_at(bit_array: bytes, bits: int, idx: int) -> int:
    """Read the `bits`-wide status at token index `idx` (LSB-first within each byte, per spec)."""
    per_byte = 8 // bits
    byte_i, slot = divmod(idx, per_byte)
    if byte_i >= len(bit_array):
        raise BundleFormatError("status index is beyond the end of the status list")
    return (bit_array[byte_i] >> (slot * bits)) & ((1 << bits) - 1)


def verify_status_snapshot(status_list_token: str, *, expected_uri: str, index: int,
                           issuer_pubkey: bytes, now: Optional[int] = None,
                           receipt_issuer_pubkey: Optional[bytes] = None) -> dict:
    """Verify a Status List Token snapshot and read one token's status, fully offline.

    Checks, fail-closed: compact-JWS shape, `typ` == ``statuslist+jwt``, EdDSA signature under
    ``issuer_pubkey``, `sub` == ``expected_uri`` (a list for a different URI proves nothing),
    `bits` ∈ {1,2,4,8}, zlib decode, index in range. Freshness: `iat`/`exp`/`ttl` are returned;
    `fresh` is None unless ``now`` (POSIX seconds) is supplied, then it is
    ``iat <= now`` AND ``now < exp`` (if exp) AND ``now <= iat + ttl`` (if ttl).

    **Trust-anchor separation (v1.9.1, external review #8/#12):** a status list signed by the
    SAME key that signed the receipt carries no *independent* revocation assurance — the issuer
    simply attests its own "still valid" state, and can flip it at will. Pass
    ``receipt_issuer_pubkey`` (the bundle's signing key) and the result reports
    ``self_issued=True`` when the status issuer key equals it. This is REPORTED, not fatal — the
    relying party decides whether self-issued revocation is acceptable for its threat model (it
    often is not; a distinct, independently-operated status authority is the stronger anchor).

    Returns ``{ok, status, status_label, fresh, self_issued, iat, exp, ttl, detail}`` — ``ok``
    covers signature + structure + lookup; combining ``ok`` with ``fresh``/``self_issued`` is the
    caller's policy.
    """
    result = {"ok": False, "status": None, "status_label": None, "fresh": None,
              "self_issued": None, "iat": None, "exp": None, "ttl": None, "detail": ""}
    if receipt_issuer_pubkey is not None:
        # hmac.compare_digest for a constant-time compare of the two public keys (defensive; the
        # values are public, but consistent with the codebase's compare discipline).
        import hmac as _hmac  # noqa: PLC0415
        # SYMMETRISCHER Typ-Guard: beide MUESSEN bytes/bytearray sein, sonst crasht bytes(str) mit TypeError
        # statt fail-closed (verify_status_snapshot deklariert 'never crashes'). Non-bytes receipt_issuer_pubkey
        # (str/int/list) → self_issued bleibt False (kein Crash, kein Fake-True).
        result["self_issued"] = (isinstance(issuer_pubkey, (bytes, bytearray))
                                 and isinstance(receipt_issuer_pubkey, (bytes, bytearray))
                                 and len(issuer_pubkey) == len(receipt_issuer_pubkey)
                                 and _hmac.compare_digest(bytes(issuer_pubkey),
                                                          bytes(receipt_issuer_pubkey)))
    if status_list_token.count(".") != 2:
        result["detail"] = "not a compact JWS"
        return result
    header_b64, payload_b64, sig_b64 = status_list_token.split(".")
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except (ValueError, TypeError, json.JSONDecodeError):
        result["detail"] = "malformed status list token"
        return result
    if not isinstance(header, dict) or not isinstance(payload, dict):
        result["detail"] = "malformed status list token"
        return result
    if header.get("typ") != TYP:
        result["detail"] = f"status list token typ must be '{TYP}'"
        return result
    if header.get("alg") != "EdDSA":
        result["detail"] = f"status list token alg {header.get('alg')!r} not supported (EdDSA only)"
        return result
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        sig_ok = verify_ed25519(issuer_pubkey, sig, signing_input)
    except ValueError:
        sig_ok = False
    if not sig_ok:
        result["detail"] = "status list token signature invalid"
        return result

    if payload.get("sub") != expected_uri:
        result["detail"] = "status list token sub does not match the referenced uri"
        return result
    iat, exp, ttl = payload.get("iat"), payload.get("exp"), payload.get("ttl")
    result["iat"], result["exp"], result["ttl"] = iat, exp, ttl
    if isinstance(iat, bool) or not isinstance(iat, int):
        result["detail"] = "status list token iat missing or not an integer"
        return result
    # v1.6 (external review): exp/ttl must be integers OR absent — a string "exp" that LOOKS
    # like an expiry but silently never enforces is a downgrade vector, not a tolerable input.
    for _name, _val in (("exp", exp), ("ttl", ttl)):
        if _val is not None and (isinstance(_val, bool) or not isinstance(_val, int)):
            result["detail"] = f"status list token {_name} must be an integer when present"
            return result

    sl = payload.get("status_list")
    if not isinstance(sl, dict):
        result["detail"] = "status_list claim missing"
        return result
    bits = sl.get("bits")
    if bits not in _ALLOWED_BITS:
        result["detail"] = f"status_list bits must be one of {_ALLOWED_BITS}"
        return result
    if not isinstance(sl.get("lst"), str):
        result["detail"] = "status_list lst missing"
        return result
    try:
        # BOUNDED decompression (release-review fix #7, CWE-409): a tiny zlib input can expand to gigabytes.
        # Cap the output and reject anything larger than a generous status-list size, instead of an unbounded
        # zlib.decompress() that a decompression-bomb could use to exhaust memory.
        _dobj = zlib.decompressobj()
        bit_array = _dobj.decompress(_b64url_decode(sl["lst"]), _MAX_STATUS_LIST_BYTES)
        if _dobj.unconsumed_tail:
            result["detail"] = "status_list lst exceeds the maximum decompressed size"
            return result
    except (ValueError, TypeError, zlib.error):
        result["detail"] = "status_list lst is not valid base64url(zlib(...))"
        return result
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        result["detail"] = "status index must be a non-negative integer"
        return result
    try:
        status = _status_at(bit_array, bits, index)
    except BundleFormatError as exc:
        result["detail"] = str(exc)
        return result

    result["ok"] = True
    result["status"] = status
    result["status_label"] = STATUS_LABELS.get(status, f"0x{status:02x}")
    if now is not None:
        # v1.6 (external review): a token with NEITHER exp NOR ttl is unbounded — "fresh
        # forever" was misleading (stale-snapshot replay). Without a bound, freshness CANNOT
        # be judged: fresh stays None and the relying party must impose its own max age.
        if exp is None and ttl is None:
            result["fresh"] = None
        else:
            fresh = iat <= now
            if exp is not None:
                fresh = fresh and now < exp
            if ttl is not None:
                fresh = fresh and now <= iat + ttl
            result["fresh"] = fresh
    result["detail"] = f"status {result['status_label']} at index {index}"
    return result


def issue_status_list_token(statuses: list, *, uri: str, signer, iat: int, bits: int = 1,
                            exp: Optional[int] = None, ttl: Optional[int] = None) -> str:
    """Issue a Status List Token (emit side, for tests/self-hosted lists). ``statuses`` is a list
    of small ints (< 2**bits); ``signer`` an Ed25519 private key; ``iat`` explicit POSIX seconds
    (the library never samples wall clocks for signatures). zlib level 9 per the spec's example."""
    if bits not in _ALLOWED_BITS:
        raise BundleFormatError(f"bits must be one of {_ALLOWED_BITS}")
    if isinstance(iat, bool) or not isinstance(iat, int):
        raise BundleFormatError("iat must be a POSIX timestamp integer")
    per_byte = 8 // bits
    arr = bytearray((len(statuses) + per_byte - 1) // per_byte)
    for i, s in enumerate(statuses):
        if isinstance(s, bool) or not isinstance(s, int) or not 0 <= s < (1 << bits):
            raise BundleFormatError(f"status value {s!r} does not fit in {bits} bit(s)")
        byte_i, slot = divmod(i, per_byte)
        arr[byte_i] |= s << (slot * bits)
    payload = {"sub": uri, "iat": iat,
               "status_list": {"bits": bits, "lst": _b64url(zlib.compress(bytes(arr), 9))}}
    if exp is not None:
        payload["exp"] = exp
    if ttl is not None:
        payload["ttl"] = ttl
    header = {"alg": "EdDSA", "typ": TYP}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))
