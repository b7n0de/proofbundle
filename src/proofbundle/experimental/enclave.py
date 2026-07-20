"""TEE-attestation bridge — bind a receipt to hardware-attested execution (v2.0 PREVIEW).

This closes the one gap a software-only receipt structurally has: it proves *who signed these
bytes and that nothing changed*, but not *that the computation ran untampered*. A Trusted
Execution Environment (Intel TDX, an NVIDIA confidential-computing GPU, …) can attest the latter.
This module lets a receipt carry `assurance_level = enclave_attested` in a way a relying party
can actually check — offline, standards-native, vendor-neutral.

**Scope, stated with the same honesty as the rest of proofbundle — read this before trusting it.**
proofbundle does NOT parse or appraise raw hardware evidence (a TDX DCAP quote, an NVIDIA GPU
attestation report). Appraising raw evidence needs vendor libraries, live collateral, and TCB
policy — it is the job of a **Verifier** in the IETF RATS architecture (RFC 9334). This module
implements the RATS **Passport model**: the Verifier appraises the evidence out of band and issues
a signed **Attestation Result**; proofbundle verifies that Attestation Result offline against the
Verifier's public key (a supplied trust anchor, exactly like every other anchor in
docs/TRUST_ANCHORS.md) and checks that it is bound to *this* receipt. So the chain of trust is:
you trust the Verifier's key → the Verifier's result says the enclave was genuine → the result's
nonce binds it to your receipt. proofbundle checks the last two links; the first is your anchor.

**Wire format (v2.0 preview — subject to change).** The Attestation Result is an EAT
(Entity Attestation Token, RFC 9711) in its **JSON/JWS** encoding, signed with **EdDSA** (the same
primitive as everything else here — no new dependency). Claims used:
  - ``eat_nonce`` (RFC 9711 §4.1) — the binding: it MUST equal ``enclave_binding_for(bundle)``,
    a base64url SHA-256 over the receipt's exact signed payload. Practically, the enclave places
    this value in the hardware quote's user-data (Intel TDX ``REPORTDATA`` / an NVIDIA GPU report
    nonce) when it runs the eval, so "this hardware ran the computation that produced this receipt"
    is cryptographically tied. proofbundle only checks the EAT-level equality — it does not see
    the raw quote.
  - ``eat_profile`` (RFC 9711 §4.3.2) — a profile URI identifying the appraisal semantics; a
    relying party MAY pin an expected profile.
  - ``ueid`` (optional) — the attested entity/enclave id, reported, not interpreted.
  - a ``tier`` string (this preview's stand-in for the AR4SI/EAR trustworthiness tier, which are
    still IETF Internet-Drafts) — REPORTED verbatim, never interpreted as a guarantee.
  - optional ``iat``/``exp`` — freshness, reported and only judged when the caller passes ``now``
    (offline verifier, no trusted clock — same discipline as the status-list module).

What this does NOT establish, and must never be claimed: that the enclave is genuine (that is the
Verifier's appraisal, which you trust via its key), that the TEE vendor's root of trust is sound,
or that the eval inside the enclave was well-designed or honest. It raises the assurance floor from
"the issuer says so" to "a Verifier you trust attested the enclave, bound to this receipt" — no
further.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Optional

from .._strict_json import loads_strict
from ..errors import BundleFormatError, ProofBundleError
from ..signature import verify_ed25519

__all__ = ["EAT_TYP", "enclave_binding_for", "verify_enclave_attestation",
           "issue_enclave_attestation"]

EAT_TYP = "eat+jwt"                       # RFC 9711 media type application/eat+jwt
_BINDING_DOMAIN = b"proofbundle/v2/enclave-binding\x00"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def enclave_binding_for(bundle: dict) -> str:
    """The value an Attestation Result's ``eat_nonce`` MUST carry to be bound to ``bundle``.

    = base64url(SHA-256(domain || the bundle's exact signed payload bytes)). This is what an
    enclave puts in its hardware quote's user-data (TDX REPORTDATA / GPU report nonce) at run
    time, so the resulting Attestation Result is tied to this exact receipt. Fits the RFC 9711
    JSON ``eat_nonce`` size window (a 43-char base64url of 32 bytes, well within 8..88).
    """
    if not isinstance(bundle, dict) or "payload_b64" not in bundle:
        raise BundleFormatError("enclave_binding_for needs a bundle dict with payload_b64")
    try:
        payload = base64.b64decode(bundle["payload_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("bundle.payload_b64 is not valid base64") from exc
    return _b64url(hashlib.sha256(_BINDING_DOMAIN + payload).digest())


def _match_nonce(eat_nonce, expected: str) -> bool:
    """RFC 9711 eat_nonce is a text string OR an array of text strings — accept either, match any."""
    if isinstance(eat_nonce, str):
        return eat_nonce == expected
    if isinstance(eat_nonce, list):
        return any(isinstance(x, str) and x == expected for x in eat_nonce)
    return False


def verify_enclave_attestation(eat_jws: str, *, verifier_pubkey: bytes, expected_binding: str,
                               expected_profile: Optional[str] = None,
                               now: Optional[int] = None) -> dict:
    """Verify a Verifier-signed EAT Attestation Result and its binding to a receipt — offline.

    Checks, fail-closed: compact-JWS shape, header ``typ`` == ``eat+jwt`` and ``alg`` == EdDSA,
    signature under ``verifier_pubkey`` (the RATS Verifier key — a supplied trust anchor),
    ``eat_nonce`` == ``expected_binding`` (from :func:`enclave_binding_for`), and — if given —
    ``eat_profile`` == ``expected_profile``. Freshness (``iat``/``exp``) is reported and only
    judged when ``now`` is supplied.

    Returns ``{ok, tier, profile, ueid, nonce_ok, fresh, iat, exp, detail}``. ``ok`` covers
    signature + typ/alg + binding (+ profile if requested); ``tier`` is the Verifier's declared
    trustworthiness tier, REPORTED verbatim — combining ``ok``/``tier``/``fresh`` into a trust
    decision is the relying party's policy.
    """
    result = {"ok": False, "tier": None, "profile": None, "ueid": None, "nonce_ok": False,
              "fresh": None, "iat": None, "exp": None, "detail": ""}
    if not isinstance(eat_jws, str) or eat_jws.count(".") != 2:
        result["detail"] = "not a compact JWS"
        return result
    header_b64, payload_b64, sig_b64 = eat_jws.split(".")
    try:
        header = loads_strict(_b64url_decode(header_b64))   # WP-C1: dup keys fail-closed
        claims = loads_strict(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except ProofBundleError as exc:
        # adversarial re-audit round 4: catch the BASE ProofBundleError, not just BundleFormatError — a node-heavy
        # or >8MiB EAT payload makes loads_strict raise a SIBLING BudgetExceeded that escaped this verify
        # surface raw (the round-3 fix widened the CALLER evalclaim but left the surface itself un-widened).
        result["detail"] = f"malformed EAT token: {exc}"
        return result
    except (ValueError, TypeError):
        result["detail"] = "malformed EAT token"
        return result
    if not isinstance(header, dict) or not isinstance(claims, dict):
        result["detail"] = "malformed EAT token"
        return result
    if header.get("typ") != EAT_TYP:
        result["detail"] = f"EAT typ must be '{EAT_TYP}'"
        return result
    if header.get("alg") != "EdDSA":
        result["detail"] = f"EAT alg {header.get('alg')!r} not supported (EdDSA only)"
        return result

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        sig_ok = verify_ed25519(verifier_pubkey, sig, signing_input)
    except ValueError:
        sig_ok = False
    if not sig_ok:
        result["detail"] = "EAT signature invalid (verifier key mismatch?)"
        return result

    result["tier"] = claims.get("tier")
    result["profile"] = claims.get("eat_profile")
    result["ueid"] = claims.get("ueid")
    iat, exp = claims.get("iat"), claims.get("exp")
    result["iat"], result["exp"] = iat, exp

    if not _match_nonce(claims.get("eat_nonce"), expected_binding):
        result["detail"] = "eat_nonce does not bind this receipt (attestation is for other bytes)"
        return result
    result["nonce_ok"] = True

    if expected_profile is not None and claims.get("eat_profile") != expected_profile:
        result["detail"] = "eat_profile does not match the expected profile"
        return result

    for _name, _val in (("iat", iat), ("exp", exp)):
        if _val is not None and (isinstance(_val, bool) or not isinstance(_val, int)):
            result["detail"] = f"EAT {_name} must be an integer when present"
            return result
    if now is not None:
        if exp is None:
            result["fresh"] = None            # unbounded — cannot judge (relying-party policy)
        else:
            result["fresh"] = (iat is None or iat <= now) and now < exp

    result["ok"] = True
    result["detail"] = f"enclave attestation verified (tier={result['tier']!r})"
    return result


def issue_enclave_attestation(binding: str, signer, *, profile: str, tier: str,
                              ueid: Optional[str] = None, iat: Optional[int] = None,
                              exp: Optional[int] = None) -> str:
    """Issue a signed EAT Attestation Result (for tests / a Verifier reference / demos).

    ``signer`` is the Verifier's Ed25519 key; ``binding`` is :func:`enclave_binding_for` of the
    receipt (the value the enclave placed in its quote user-data). In production a real Verifier
    emits this after appraising the raw TDX/GPU evidence — this helper does NOT appraise evidence,
    it only frames + signs the result, so tests and reference verifiers have a token to check.
    """
    # explizite Annotation (analog statuslist.py): die Init-Werte sind str, aber iat/exp weiter unten
    # sind int — ohne Annotation inferiert mypy dict[str, str] und lehnt die int-Zuweisungen ab (CI-mypy,
    # kein Runtime-Bug).
    claims: dict[str, str | int] = {"eat_nonce": binding, "eat_profile": profile, "tier": tier}
    if ueid is not None:
        claims["ueid"] = ueid
    if iat is not None:
        claims["iat"] = iat
    if exp is not None:
        claims["exp"] = exp
    header = {"alg": "EdDSA", "typ": EAT_TYP}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(claims).encode())
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))
