"""The integrity mechanism this reader profiles for Section 6: JWS compact serialization (RFC 7515) with
EdDSA over Ed25519 (RFC 8037), the issuer's keys taken only from the verifier's trust configuration.

Section 6 requires an inter-domain EQR to be integrity protected and bound to an authenticated issuer
"using a mechanism acceptable to the verifier" and names JWS and COSE Sign1 as examples. This reader
accepts one mechanism and refuses every other form rather than guessing: alg other than EdDSA, a
"crit" or "b64" header, and an unprotected or detached payload. Keys named in the header (jwk, jku,
x5u, x5c) are never used and never fetched (Section 15, evidence reference attacks).
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .wire import WireError, b64u_decode, decode_json

ALG = "EdDSA"
REFUSED_HEADERS = ("crit", "b64")
NEVER_USED_HEADERS = ("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256")


class JwsError(ValueError):
    """A JWS this reader refuses, with the reason."""


def split(compact):
    """(protected header object, payload bytes, signing input bytes, signature bytes) of a compact JWS."""
    if not isinstance(compact, str) or not compact.isascii():
        raise JwsError("a compact JWS is an ASCII string")
    parts = compact.split(".")
    if len(parts) != 3:
        raise JwsError(f"a compact JWS has three parts, this one {len(parts)}")
    h64, p64, s64 = parts
    if p64 == "":
        raise JwsError("detached payload: the receipt itself must be signed")
    try:
        header = decode_json(b64u_decode(h64))
        payload = b64u_decode(p64)
        signature = b64u_decode(s64)
    except WireError as exc:
        raise JwsError(f"JWS part refused: {exc}") from exc
    if not isinstance(header, dict):
        raise JwsError("the protected header is not a JSON object")
    return header, payload, (h64 + "." + p64).encode("ascii"), signature


def header_findings(header):
    """Refusals and notes for a protected header; the refusals make the signature unusable."""
    refusals, notes = [], []
    if header.get("alg") != ALG:
        refusals.append(f"alg {header.get('alg')!r} is not the mechanism this reader accepts ({ALG})")
    for h in REFUSED_HEADERS:
        if h in header:
            refusals.append(f"header {h!r} is not supported and is refused rather than ignored")
    if not isinstance(header.get("kid"), str) or not header.get("kid"):
        refusals.append("kid is missing: the issuer key is looked up by kid in the trust configuration")
    for h in NEVER_USED_HEADERS:
        if h in header:
            notes.append(f"header {h!r} present: not used and not dereferenced (Section 15)")
    return refusals, notes


def verify_ed25519(jwk, signing_input: bytes, signature: bytes) -> bool:
    """True when the signature verifies under the configured public key."""
    if not (isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"):
        raise JwsError("the configured key is not an Ed25519 OKP key")
    try:
        x = b64u_decode(jwk.get("x"))
    except WireError as exc:
        raise JwsError(f"configured key: {exc}") from exc
    if len(x) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(x).verify(signature, signing_input)
    except InvalidSignature:
        return False
    return True
