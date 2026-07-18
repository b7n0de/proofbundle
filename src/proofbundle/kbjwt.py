"""Key Binding JWT (KB-JWT) verification per RFC 9901 §4.3 — v1.2.

A Key Binding JWT proves that whoever presented an SD-JWT controls the holder
key the issuer bound into the credential (the ``cnf`` claim). Before v1.2 a
trailing KB-JWT was silently ignored; that is a downgrade risk — a bundle that
*carries* holder binding must not verify as OK without the binding being
checked. This module closes issue #1, fail-closed and fully offline.

RFC 9901 requirements enforced here (verifier side, §4.3):
  - the KB-JWT is the LAST ``~``-separated part of the compact serialization;
    a compact form ending in ``~`` has NO key binding (§4.1: the trailing tilde
    is the no-KB marker).
  - header ``typ`` MUST be ``kb+jwt``; ``alg`` MUST NOT be ``none`` (we support
    EdDSA/Ed25519 only, consistent with the rest of proofbundle).
  - payload MUST contain ``iat`` (number), ``aud``, ``nonce`` and ``sd_hash``.
  - ``sd_hash`` = base64url(H(US-ASCII bytes of the presented
    ``<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~``)) — everything up
    to AND INCLUDING the tilde immediately before the KB-JWT, hashed with the
    SD-JWT's ``_sd_alg`` hash. This binds the KB-JWT to the *presented
    disclosure set*: swapping or dropping a disclosure after signing breaks it.
  - the signature is verified with the holder key from the issuer-signed
    payload's ``cnf.jwk`` (RFC 7800; OKP/Ed25519), or an explicitly supplied
    holder key. The cnf key wins when both are available — the issuer's binding
    is the source of truth.

Out of scope, stated honestly: aud/nonce *value* policy is the verifier's
(pass ``expected_aud`` / ``expected_nonce`` to enforce); no clock-based ``iat``
freshness window (a pure-offline verifier has no trusted clock); no non-EdDSA
algorithms; no x5c/kid holder-key resolution.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Optional, Tuple

from ._strict_json import loads_strict
from .errors import ProofBundleError
from .signature import verify_ed25519

__all__ = ["split_key_binding", "verify_key_binding", "holder_key_from_cnf"]

_HASH_ALG = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def split_key_binding(compact: str) -> Tuple[str, Optional[str]]:
    """Split a compact SD-JWT into (sd_part, kb_jwt_or_None).

    ``sd_part`` always ends with the tilde that terminates the disclosure list —
    exactly the bytes the KB-JWT's ``sd_hash`` commits to. A compact form that
    ends with ``~`` carries no key binding (RFC 9901 §4.1).
    """
    if compact.endswith("~"):
        return compact, None
    head, _, tail = compact.rpartition("~")
    if not head or tail.count(".") != 2:
        # No tilde at all, or the trailing segment is not a JWS — not a KB-JWT.
        return compact, None
    return head + "~", tail


def holder_key_from_cnf(issuer_payload: dict) -> Optional[bytes]:
    """Extract the raw 32-byte Ed25519 holder key from a ``cnf.jwk`` claim (RFC 7800).

    Returns None if there is no usable OKP/Ed25519 confirmation key.
    """
    cnf = issuer_payload.get("cnf")
    if not isinstance(cnf, dict):
        return None
    jwk = cnf.get("jwk")
    if not isinstance(jwk, dict):
        return None
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    x = jwk.get("x")
    if not isinstance(x, str):
        return None
    try:
        raw = _b64url_decode(x)
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def verify_key_binding(
    compact: str,
    holder_pubkey: Optional[bytes] = None,
    *,
    expected_aud: Optional[str] = None,
    expected_nonce: Optional[str] = None,
) -> dict:
    """Verify the Key Binding JWT of a compact SD-JWT presentation.

    Returns a dict: ``present`` (a KB-JWT is attached), ``ok`` (all checks
    passed), ``detail``, plus ``aud``/``nonce``/``iat`` for caller policy.
    ``ok`` is only meaningful when ``present`` is True; an absent KB-JWT yields
    ``present=False, ok=False`` and the caller decides whether that is fatal.

    The holder key comes from the issuer-signed payload's ``cnf.jwk`` when
    available (the issuer's binding is authoritative), else from
    ``holder_pubkey``. If neither exists the check fails — never skips.
    """
    result = {"present": False, "ok": False, "detail": "", "aud": None, "nonce": None, "iat": None}
    if not isinstance(compact, str):
        # RE-GATE never-raise (breadth sweep): a non-str `compact` presentation is malformed input — a
        # fail-closed verdict (present=False, ok=False), never a raw AttributeError from split_key_binding's
        # string operations (e.g. `.endswith`). This dict-returning surface must always return a verdict.
        result["detail"] = "compact presentation must be a string (non-str is malformed, fail-closed)"
        return result
    sd_part, kb = split_key_binding(compact)
    if kb is None:
        result["detail"] = "no key binding JWT attached"
        return result
    result["present"] = True

    issuer_jwt = sd_part.split("~", 1)[0]
    if issuer_jwt.count(".") != 2:
        result["detail"] = "not a compact SD-JWT"
        return result
    try:
        # F12 (2026-07-12): loads_strict rejects a DUPLICATE key fail-closed. The issuer payload's `cnf`
        # is the holder-binding key source (holder_key_from_cnf below); with plain last-wins json.loads a
        # duplicated `cnf` let an attacker-controlled key win. BundleFormatError is NOT a ValueError, so it
        # is caught explicitly here → the KB-JWT verification fails (ok stays False), never a raw traceback.
        issuer_payload = loads_strict(_b64url_decode(issuer_jwt.split(".")[1]))
        kb_header_b64, kb_payload_b64, kb_sig_b64 = kb.split(".")
        kb_header = loads_strict(_b64url_decode(kb_header_b64))
        kb_payload = loads_strict(_b64url_decode(kb_payload_b64))
        kb_sig = _b64url_decode(kb_sig_b64)
    except ProofBundleError:  # incl. BudgetExceeded (RE-GATE never-raise) + BundleFormatError (dup key)
        result["detail"] = "KB-JWT or issuer JWT rejected (duplicate JSON key or over verification budget)"
        return result
    except (ValueError, TypeError, json.JSONDecodeError):
        result["detail"] = "malformed KB-JWT or issuer JWT"
        return result
    if not isinstance(kb_header, dict) or not isinstance(kb_payload, dict) \
            or not isinstance(issuer_payload, dict):
        result["detail"] = "malformed KB-JWT or issuer JWT"
        return result

    # Header: typ MUST be kb+jwt; alg MUST NOT be none; we support EdDSA only.
    if kb_header.get("typ") != "kb+jwt":
        result["detail"] = "KB-JWT typ must be 'kb+jwt'"
        return result
    alg = kb_header.get("alg")
    if alg != "EdDSA":
        result["detail"] = f"KB-JWT alg {alg!r} not supported (EdDSA only)"
        return result

    # Payload: iat, aud, nonce, sd_hash are REQUIRED (RFC 9901 §4.3).
    iat = kb_payload.get("iat")
    aud = kb_payload.get("aud")
    nonce = kb_payload.get("nonce")
    sd_hash = kb_payload.get("sd_hash")
    result["aud"], result["nonce"], result["iat"] = aud, nonce, iat
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        result["detail"] = "KB-JWT iat missing or not a number"
        return result
    # RFC 9901 §4.3: the KB-JWT `aud` is a SINGLE string (narrower than RFC 7519's string-or-array). Reject a
    # JSON array for strict conformance (release-review fix #3).
    if not isinstance(aud, str) or not aud:
        result["detail"] = "KB-JWT aud missing or not a single string (RFC 9901 §4.3)"
        return result
    if not isinstance(nonce, str) or not nonce:
        result["detail"] = "KB-JWT nonce missing"
        return result
    if not isinstance(sd_hash, str) or not sd_hash:
        result["detail"] = "KB-JWT sd_hash missing"
        return result

    # sd_hash binds the KB-JWT to the exact presented SD-JWT + disclosure set.
    sd_alg = issuer_payload.get("_sd_alg", "sha-256")
    if sd_alg not in _HASH_ALG:
        result["detail"] = f"unsupported _sd_alg {sd_alg}"
        return result
    h = hashlib.new(_HASH_ALG[sd_alg])
    h.update(sd_part.encode("ascii"))
    if _b64url_nopad(h.digest()) != sd_hash:
        result["detail"] = "sd_hash does not match the presented SD-JWT and disclosures"
        return result

    # Caller policy on aud/nonce values (only enforced when expectations given). `aud` is guaranteed a single
    # non-empty string above (RFC 9901 §4.3), so a direct comparison suffices (no list handling).
    if expected_aud is not None and expected_aud != aud:
        result["detail"] = "KB-JWT aud does not match the expected audience"
        return result
    if expected_nonce is not None and nonce != expected_nonce:
        result["detail"] = "KB-JWT nonce does not match the expected nonce"
        return result

    # Signature with the holder key — cnf.jwk is authoritative when present.
    key = holder_key_from_cnf(issuer_payload)
    key_source = "cnf.jwk"
    if key is None:
        key = holder_pubkey
        key_source = "supplied holder key"
    if key is None:
        result["detail"] = "KB-JWT present but no holder key (no cnf.jwk and none supplied)"
        return result
    signing_input = f"{kb_header_b64}.{kb_payload_b64}".encode("ascii")
    try:
        sig_ok = verify_ed25519(key, kb_sig, signing_input)
    except ValueError:
        sig_ok = False
    if not sig_ok:
        result["detail"] = f"KB-JWT signature invalid ({key_source})"
        return result

    result["ok"] = True
    result["detail"] = f"key binding valid ({key_source})"
    return result
