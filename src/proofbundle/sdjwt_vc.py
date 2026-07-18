"""SD-JWT VC minimal profile — 3.2.0 O7 (EXPERIMENTAL).

A relying-party profile check for SD-JWT Verifiable Credentials on top of the existing key-binding verifier
(``kbjwt.py``). It enforces the VC-specific rules:

  - the issuer JWT header ``typ`` MUST be ``dc+sd-jwt`` (the SD-JWT VC media type);
  - the ``vct`` (verifiable credential type) claim is REQUIRED and MUST be on the relying party's allowlist —
    an unknown vct is fail-closed, never trusted;
  - type-metadata integrity: when required, the vct's metadata is trusted ONLY from an offline cache the
    relying party passes in, matched by a ``vct#integrity`` digest — NEVER fetched;
  - universal holder binding: an SD-JWT presented under this profile WITHOUT a valid key binding is FAIL
    (an unknown profile with SD-JWT but no binding does not verify).

SSRF protection is STRUCTURAL: this module performs NO network I/O whatsoever. A ``vct`` that looks like a URL
is treated as an opaque type identifier and matched against the allowlist / offline cache — it is never
dereferenced. There is no code path that opens a socket, so a malicious ``vct`` / metadata URL cannot drive a
request. Offline metadata is supplied by the caller as a plain dict.

No-Overclaim: a passing profile check attests the credential's type is allowlisted and (optionally) its
metadata integrity and holder binding hold — never that the credential's CLAIMS are true.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from ._strict_json import loads_strict
from .errors import ProofBundleError

SD_JWT_VC_TYP = "dc+sd-jwt"
_POLICY_KEYS = {"vctAllowlist", "requireTypeMetadataIntegrity", "requireKeyBinding",
                "requireIssuerSignature"}


class SdjwtVcError(ProofBundleError):
    """An SD-JWT VC profile policy is malformed, or a required profile check could not be enforced."""


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def validate_vc_policy(policy: Any) -> list[str]:
    """Fail-closed validation of an SD-JWT VC profile policy (empty = valid)."""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    for k in policy:
        if k not in _POLICY_KEYS:
            errors.append(f"unknown policy key {k!r}")
    va = policy.get("vctAllowlist")
    if not (isinstance(va, list) and va and all(isinstance(x, str) and x for x in va)):
        errors.append("vctAllowlist must be a non-empty list of allowed vct strings")
    for b in ("requireTypeMetadataIntegrity", "requireKeyBinding", "requireIssuerSignature"):
        if b in policy and not isinstance(policy[b], bool):
            errors.append(f"{b} must be a boolean")
    return errors


def _issuer_header_payload(compact: str) -> tuple[dict, dict]:
    """Parse the issuer-signed JWT header + payload from a compact SD-JWT (the part before the first ``~``).
    Fail-closed: a malformed JWT, non-object header/payload, or a duplicate JSON key raises SdjwtVcError."""
    issuer_jwt = compact.split("~", 1)[0]
    parts = issuer_jwt.split(".")
    if len(parts) != 3:
        raise SdjwtVcError("issuer SD-JWT is not a three-part compact JWT")
    try:
        header = loads_strict(_b64url_decode(parts[0]))
        payload = loads_strict(_b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        raise SdjwtVcError("issuer SD-JWT header/payload is not valid JSON (or has duplicate keys)") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise SdjwtVcError("issuer SD-JWT header and payload must be JSON objects")
    return header, payload


def check_vc_profile(compact: str, policy: dict, *, offline_metadata: dict | None = None) -> dict:
    """Check an SD-JWT VC against the profile policy. NO network I/O — SSRF-safe by construction.

    Returns ``{ok, typ_ok, vct_ok, metadata_integrity_ok, vct, errors}``. ``metadata_integrity_ok`` is None
    when the policy does not require it. A vct is matched as an OPAQUE identifier against ``vctAllowlist``;
    if it is a URL it is NOT dereferenced. When ``requireTypeMetadataIntegrity`` is set, the vct's metadata is
    resolved ONLY from ``offline_metadata`` (a caller dict {vct: {"bytes_b64": ..., "integrity": "sha256-..."}})
    and its sha256 must match the declared integrity — a missing offline entry is fail-closed FAIL, never a
    fetch. Read ``ok`` — never an individual field alone."""
    perrs = validate_vc_policy(policy)
    if perrs:
        raise SdjwtVcError("invalid SD-JWT VC policy: " + "; ".join(perrs))

    r: dict[str, Any] = {"ok": False, "typ_ok": None, "vct_ok": None,
                         "metadata_integrity_ok": None, "vct": None, "errors": []}
    try:
        header, payload = _issuer_header_payload(compact)
    except SdjwtVcError as exc:
        r["errors"].append(str(exc))
        return r

    r["typ_ok"] = header.get("typ") == SD_JWT_VC_TYP
    if not r["typ_ok"]:
        r["errors"].append(f"issuer JWT typ is {header.get('typ')!r}, expected {SD_JWT_VC_TYP!r}")
    # alg=none / no alg is never acceptable (kbjwt enforces this on the KB-JWT; assert on the issuer header too).
    # Case-insensitive + non-string guard (release-review #3): 'NONE'/'None'/'nOnE' and a non-string alg are all
    # rejected here — the real crypto gate (sdjwt.verify_sd_jwt, EdDSA/ES256 since Finding 20) already fails such
    # a credential in the full verify path, but check_vc_profile is a public function and must not itself
    # green-light a none-alg header.
    _alg = header.get("alg")
    if not isinstance(_alg, str) or _alg.strip().lower() == "none":
        r["errors"].append("issuer JWT alg must not be 'none' / absent")

    vct = payload.get("vct")
    r["vct"] = vct if isinstance(vct, str) else None
    allow = policy.get("vctAllowlist") or []
    r["vct_ok"] = isinstance(vct, str) and vct in allow
    if not r["vct_ok"]:
        r["errors"].append(f"vct {vct!r} is not on the relying party's vctAllowlist (unknown type, fail-closed)")

    if policy.get("requireTypeMetadataIntegrity"):
        entry = (offline_metadata or {}).get(vct) if isinstance(vct, str) else None
        if not isinstance(entry, dict) or "bytes_b64" not in entry or "integrity" not in entry:
            r["metadata_integrity_ok"] = False
            r["errors"].append(
                "requireTypeMetadataIntegrity but no offline metadata entry for this vct — never fetched "
                "(SSRF-safe), fail-closed")
        else:
            try:
                raw = base64.b64decode(entry["bytes_b64"], validate=True)
                got = "sha256-" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
                r["metadata_integrity_ok"] = (got == entry["integrity"])
            except Exception:  # noqa: BLE001
                r["metadata_integrity_ok"] = False
            if r["metadata_integrity_ok"] is False:
                r["errors"].append("type metadata integrity digest mismatch (offline cache)")

    r["ok"] = bool(r["typ_ok"] and r["vct_ok"]
                   and not any(e.startswith("issuer JWT alg") for e in r["errors"])
                   and r["metadata_integrity_ok"] is not False)
    return r


def verify_sdjwt_vc(compact: str, policy: dict, *, issuer_pubkey: bytes | None = None,
                    holder_pubkey: bytes | None = None,
                    expected_aud: str | None = None, expected_nonce: str | None = None,
                    offline_metadata: dict | None = None) -> dict:
    """Full SD-JWT VC relying-party check: the ISSUER SIGNATURE (sdjwt.verify_sd_jwt) AND the VC PROFILE
    (check_vc_profile) AND, when the policy requires it, the holder KEY BINDING (kbjwt.verify_key_binding).
    NO network I/O.

    ISSUER AUTHENTICITY (release-review fix): ``requireIssuerSignature`` defaults to True. The RP MUST supply
    ``issuer_pubkey`` — its trusted anchor for the issuer (this module never fetches issuer metadata: SSRF-safe).
    Without it the check is FAIL (``ok=False``): a credential whose issuer signature is not verified is not
    authenticated, no matter how well-formed. Earlier this function returned ok=True for a fully self-issued,
    garbage-signed credential because it only parsed the issuer JWT; it now cryptographically verifies it.

    ``requireKeyBinding`` defaults to True (a VC without a valid holder binding is FAIL — the holder key is taken
    from ``cnf.jwk`` inside the issuer payload, so it is only trustworthy once the issuer signature above is
    verified). Returns ``{ok, profile, issuer, binding}``; read ``ok`` — never an individual field alone."""
    from . import kbjwt, sdjwt  # noqa: PLC0415
    if not isinstance(policy, dict):
        # RE-GATE never-raise (policy type-confusion, mirror decision/outcome/relation_statement): a non-dict
        # policy must be a fail-closed verdict, not a raw AttributeError from policy.get(...). A requested-but-
        # malformed policy is never a silent pass.
        return {"ok": False, "profile": None, "issuer": None, "binding": None,
                "detail": "policy must be a JSON object — malformed policy argument (fail-closed)"}
    require_binding = policy.get("requireKeyBinding", True)
    require_issuer_sig = policy.get("requireIssuerSignature", True)
    profile = check_vc_profile(compact, policy, offline_metadata=offline_metadata)

    issuer = None
    issuer_ok = True
    if require_issuer_sig:
        if issuer_pubkey is None:
            issuer = {"sig_checked": False, "sig_ok": None,
                      "detail": "issuer_pubkey (trust anchor) required — the issuer signature cannot be "
                                "verified without it, so the credential is not authenticated (fail-closed)"}
            issuer_ok = False
        else:
            issuer = sdjwt.verify_sd_jwt(compact, issuer_pubkey)
            issuer_ok = bool(issuer.get("sig_checked") and issuer.get("sig_ok"))

    binding = None
    binding_ok = True
    if require_binding:
        binding = kbjwt.verify_key_binding(compact, holder_pubkey,
                                           expected_aud=expected_aud, expected_nonce=expected_nonce)
        binding_ok = bool(binding.get("present") and binding.get("ok"))

    return {"ok": bool(profile["ok"] and issuer_ok and binding_ok),
            "profile": profile, "issuer": issuer, "binding": binding}
