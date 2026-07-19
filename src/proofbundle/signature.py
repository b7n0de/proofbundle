"""Ed25519 + ECDSA P-256 (ES256) signature verification.

Wraps ``cryptography`` so we never implement signature math ourselves. Only
verification is exposed as public API; key generation and signing live in the
examples and are meant for tests and local demos, not for production issuance.

ES256 (Finding 20 / issue #27, PB-2026-07-15): ECDSA P-256 issuer-signature
verification for SD-JWT / SD-JWT VC interop (RFC 7518 §3.4 — the JWS wire
format is a fixed-width 64-byte ``R || S`` concatenation, NOT the DER
encoding ``cryptography`` expects natively; ``verify_ecdsa_p256`` converts
before calling into the library, never re-implementing ECDSA itself).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

__all__ = ["verify_ed25519", "verify_ecdsa_p256"]


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature over ``message``.

    ``public_key`` must be the 32 byte raw Ed25519 public key and ``signature``
    the 64 byte raw signature. Any malformed input returns False rather than
    raising, so callers get a boolean per check.
    """
    if (not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray))
            or not isinstance(message, (bytes, bytearray))):
        return False   # non-bytes (e.g. None) is malformed input → False, never a raise (contract).
        # Berkeley re-gate: ``message`` was previously unguarded — a non-bytes ``message`` (None) reached
        # cryptography's .verify(sig, data) and raised a raw TypeError that the (InvalidSignature, ValueError)
        # except did NOT catch, defeating the never-raise contract one arg past where CB-01 stopped (key/sig).
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        # CB-01 (RE-GATE never-raise): the isinstance guard admits a bytearray, but
        # Ed25519PublicKey.from_public_bytes / .verify require exact ``bytes`` and raise a raw TypeError on a
        # bytearray — which escaped every DSSE verify_* entrypoint (decision/outcome/…) as an uncaught crash,
        # defeating their never-raise contract. Coerce to bytes so a VALID bytearray key/sig VERIFIES
        # (correct) rather than crashing; mirrors verify_ecdsa_p256, which already coerces.
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False   # TypeError belt-and-suspenders: any residual raw crypto-lib type crash → False


def verify_ecdsa_p256(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid ECDSA P-256 (ES256, RFC 7518 §3.4) signature
    over ``message``.

    ``public_key`` must be the 65-byte SEC1 UNCOMPRESSED point (``0x04 || X(32) || Y(32)`` —
    the same "raw" EC public-key convention WebCrypto's ``raw`` format uses) and ``signature``
    the 64-byte raw ``R || S`` JWS signature (RFC 7518 §3.4 — fixed-width concatenation, NOT
    the ASN.1 DER encoding ``cryptography``'s ECDSA verify natively expects; converted here via
    :func:`~cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`, never
    hand-rolled). ``from_encoded_point`` also rejects a point that is not actually on the P-256
    curve (raises ``ValueError``, caught below) — a malformed/forged public key never silently
    verifies. Any malformed input returns False rather than raising, matching
    :func:`verify_ed25519`'s contract so callers get a boolean per check regardless of alg.
    """
    if (not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray))
            or not isinstance(message, (bytes, bytearray))):
        return False   # non-bytes (e.g. None) is malformed input → False, never a raise (contract).
        # Berkeley re-gate: ``message`` guard mirrors verify_ed25519 — a non-bytes ``message`` reached
        # pub.verify(sig, data) and raised a raw TypeError the (InvalidSignature, ValueError) except missed.
    if len(public_key) != 65 or bytes(public_key[:1]) != b"\x04" or len(signature) != 64:
        return False   # SEC1 uncompressed only (0x04 prefix) — compressed/hybrid points are rejected
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(public_key))
        r = int.from_bytes(bytes(signature[:32]), "big")
        s = int.from_bytes(bytes(signature[32:]), "big")
        der_sig = encode_dss_signature(r, s)
        pub.verify(der_sig, bytes(message), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False   # TypeError belt-and-suspenders: any residual raw crypto-lib type crash → False
