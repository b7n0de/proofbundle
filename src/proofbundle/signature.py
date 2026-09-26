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

__all__ = ["verify_ed25519", "verify_ed25519_pinned", "ed25519_trust_anchor_weakness",
           "verify_ecdsa_p256"]


_ED25519_P = (1 << 255) - 19          # the field prime 2**255 - 19
_ED25519_SIGN_MASK = 1 << 255         # bit 255 is the x sign, not part of y
_ED25519_Y_MASK = _ED25519_SIGN_MASK - 1


def _low_order_ed25519_y() -> frozenset:
    """The y-coordinates of the Ed25519 8-torsion subgroup (identity y=1, order-2 y=p-1, order-4 y=0,
    and the two order-8 y-values). Checking the y-VALUE (sign-independent) rejects a low-order key under
    ANY encoding — both sign variants — where a hand-kept byte-string blocklist misses the sign/field
    variants (6-lens fix-review re-break found 3 missing). Computed from the known order-8 encodings."""
    ys = {0, 1, _ED25519_P - 1}
    for h in ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"):
        ys.add(int.from_bytes(bytes.fromhex(h), "little") & _ED25519_Y_MASK)
    return frozenset(ys)


_LOW_ORDER_ED25519_Y = _low_order_ed25519_y()


def ed25519_trust_anchor_weakness(public_key) -> "str | None":
    """Why ``public_key`` cannot stand as a TRUSTED Ed25519 identity, or None when it can.

    :func:`verify_ed25519` keeps the SPEC §4a profile, which accepts small-order components and one of
    the non-canonical key encodings. That profile is right for checking a signature and wrong for a key
    a caller trusts: under a low-order key a signature made with no private key verifies. Under the
    identity point the fixed signature (R = identity, S = 0) verifies for EVERY message; under the other
    points of small order it verifies for about one message in the key's order, and a forger who varies
    the message or R finds one after a few tries. Nobody holds a private key for such a key. The rule was first written for the trust policy
    (``policy._validate_pinned_ed25519_pubkey``) and stayed there while every other place that takes a
    trusted key went without it (deep gate Z195, findings L1-Z195-01..03). It lives here now so that
    each of those places asks the same question in the same words.

    Returns ``"malformed"`` (not 32 bytes), ``"non-canonical"`` (y >= p) or ``"low-order"`` (y of the
    8-torsion subgroup, either sign), else None.

    WHAT THE CHECK BUYS BEYOND THE FORGERY. With y < p and the torsion y-values excluded, a key has
    exactly one encoding: the only points whose x-sign bit can be set without meaning anything are
    those with x = 0, and both of them (y = 1 and y = p - 1) are in the low-order set. So two different
    byte strings that pass here are two different points, and a quorum or threshold that counts
    distinct key BYTES counts distinct points.

    WHAT IT DOES NOT CHECK, on purpose. A mixed-order key (a prime-order point plus a torsion
    component) is not refused. Signing under it still needs the discrete log of the prime-order part,
    so it gives no forgery without a secret. Its owner can sign under all eight variants A + T of one
    key A (T of the 8-torsion subgroup, A itself included) by grinding each signature's nonce until
    [k]T is the identity. Each try succeeds with probability 1/ord(T), so the number of tries is
    geometric: on average ord(T) (2, 4 or 8), with no upper bound, since a signature under an order-8
    variant still needs more than n tries with probability (7/8)**n. The test on the k parity pins that
    mechanism for order 2. A 2-of-2 witness quorum met by two points of ONE secret is kept as a test
    (``DistinctPointsAreNotDistinctParties``). That is one party holding several keys, which any party
    can do by generating a second key; no signature reveals it, so a count of distinct keys is never a
    count of distinct parties."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return "malformed"
    y = int.from_bytes(bytes(public_key), "little") & _ED25519_Y_MASK   # strip the x sign bit
    if y >= _ED25519_P:
        return "non-canonical"
    if y in _LOW_ORDER_ED25519_Y:
        return "low-order"
    return None


def verify_ed25519_pinned(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """:func:`verify_ed25519` for a key the CALLER trusts: False when the key is malformed, non-canonical
    or low-order (:func:`ed25519_trust_anchor_weakness`), before any signature arithmetic. Same
    never-raise contract. Every verify path whose key is a trust anchor supplied from outside the
    signed object goes through here; the in-band key of a bundle, whose trust comes from a policy pin,
    keeps the plain SPEC §4a check."""
    if ed25519_trust_anchor_weakness(public_key) is not None:
        return False
    return verify_ed25519(public_key, signature, message)


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature over ``message``.

    ``public_key`` must be the 32 byte raw Ed25519 public key and ``signature``
    the 64 byte raw signature. Any malformed input returns False rather than
    raising, so callers get a boolean per check.
    """
    if (not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray))
            or not isinstance(message, (bytes, bytearray))):
        return False   # non-bytes (e.g. None) is malformed input → False, never a raise (contract).
        # adversarial re-audit: ``message`` was previously unguarded — a non-bytes ``message`` (None) reached
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
        # adversarial re-audit: ``message`` guard mirrors verify_ed25519 — a non-bytes ``message`` reached
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
