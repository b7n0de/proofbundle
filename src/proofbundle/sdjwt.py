"""Minimal SD-JWT selective disclosure verification.

The SD-JWT *core* is now a published standard, RFC 9901 (November 2025). This
module verifies the heart of it: that every presented Disclosure hashes to a
digest that is actually committed in the issuer-signed JWT payload, and, if an
issuer public key is supplied and the algorithm is EdDSA, that the issuer
signature over the JWT is valid.

Note the layering: RFC 9901 is the SD-JWT mechanism; **SD-JWT VC** (the
credential type profile) is still an IETF draft,
``draft-ietf-oauth-sd-jwt-vc`` — this verifier does not yet do VC-level checks.

Scope, stated honestly (see README security notes):
  - EdDSA (Ed25519) issuer signatures only.
  - Key Binding JWT verification lives in :mod:`proofbundle.kbjwt` (since
    v1.2); this module verifies issuer signature + disclosure commitments,
    and the bundle layer runs the KB check fail-closed whenever a KB-JWT is
    attached.
  - No X.509 / trust-list / status-list checks, no ``vct`` type-metadata
    resolution. Full SD-JWT VC conformance is on the roadmap.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Optional, Set

from .signature import verify_ed25519

__all__ = ["verify_sd_jwt"]

_HASH_ALG = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _digest(disclosure_b64: str, alg: str) -> str:
    h = hashlib.new(_HASH_ALG[alg])
    h.update(disclosure_b64.encode("ascii"))
    return _b64url_nopad(h.digest())


def _collect_committed_digests(node, out: Set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "_sd" and isinstance(value, list):
                out.update(d for d in value if isinstance(d, str))
            elif key == "...":
                if isinstance(value, str):
                    out.add(value)
            else:
                _collect_committed_digests(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_committed_digests(item, out)


def verify_sd_jwt(compact: str, issuer_pubkey: Optional[bytes] = None) -> dict:
    """Verify an SD-JWT compact serialization.

    Returns a dict with keys: ``structure_ok`` (disclosures all committed),
    ``sig_checked``, ``sig_ok``, ``alg`` and ``detail``.
    """
    result = {
        "structure_ok": False,
        "sig_checked": False,
        "sig_ok": False,
        "alg": None,
        "detail": "",
    }
    parts = compact.split("~")
    if len(parts) < 1 or parts[0].count(".") != 2:
        result["detail"] = "not a compact SD-JWT"
        return result

    header_b64, payload_b64, sig_b64 = parts[0].split(".")
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        result["detail"] = "malformed JWT header or payload"
        return result

    alg = header.get("alg")
    result["alg"] = alg
    sd_alg = payload.get("_sd_alg", "sha-256")
    if sd_alg not in _HASH_ALG:
        result["detail"] = f"unsupported _sd_alg {sd_alg}"
        return result

    # Disclosures are the non-empty middle parts; a trailing key-binding token
    # (which contains dots) is not a disclosure — it is verified separately by
    # proofbundle.kbjwt (bundle layer, fail-closed) since v1.2.
    disclosures = [p for p in parts[1:] if p and p.count(".") == 0]

    committed: Set[str] = set()
    _collect_committed_digests(payload, committed)

    all_committed = True
    for d in disclosures:
        try:
            parsed = json.loads(_b64url_decode(d))
        except (ValueError, json.JSONDecodeError):
            all_committed = False
            break
        if not (isinstance(parsed, list) and len(parsed) in (2, 3)):
            all_committed = False
            break
        if _digest(d, sd_alg) not in committed:
            all_committed = False
            break
    result["structure_ok"] = all_committed and bool(parts[0])

    if issuer_pubkey is not None:
        result["sig_checked"] = True
        if alg == "EdDSA":
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            try:
                result["sig_ok"] = verify_ed25519(
                    issuer_pubkey, _b64url_decode(sig_b64), signing_input
                )
            except ValueError:
                result["sig_ok"] = False
        else:
            result["detail"] = f"issuer signature alg {alg} not supported in v0.1"

    if not result["detail"]:
        result["detail"] = f"{len(disclosures)} disclosure(s)"
    return result
