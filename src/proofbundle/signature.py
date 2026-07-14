"""Ed25519 signature verification.

Wraps ``cryptography`` so we never implement signature math ourselves. Only
verification is exposed as public API; key generation and signing live in the
examples and are meant for tests and local demos, not for production issuance.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["verify_ed25519"]


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature over ``message``.

    ``public_key`` must be the 32 byte raw Ed25519 public key and ``signature``
    the 64 byte raw signature. Any malformed input returns False rather than
    raising, so callers get a boolean per check.
    """
    if not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return False   # non-bytes (e.g. None) is malformed input → False, never a raise (contract)
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
