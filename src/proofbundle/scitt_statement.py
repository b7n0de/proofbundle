"""SCITT Signed Statements over proofbundle receipts, the producer side of ``scitt-ccf/v1`` (EXPERIMENTAL).

Needs the ``[scitt]`` extra (cbor2, to read back what was written) and the RFC 8785 canonicalizer
(the ``[anchors]`` / ``[eval]`` extra, for the receipt root). Nothing here opens a network connection.

WHAT A STATEMENT IS HERE. A COSE_Sign1 (RFC 9052, tag 18) that is an RFC 9995 COSE Hash Envelope:

* payload: the receipt's anchor root, the SHA-256 of the RFC 8785 form of the bundle without its
  ``anchors`` (``anchors.receipt_canonical_root``), the root a ``receipt`` anchor stamps and the
  ``canonical_root`` that ``scitt_ccf.verify_transparent_statement`` binds a statement to;
* protected: alg (1), kid (4), CWT Claims (15, RFC 9597) with ``iss`` (1) and ``sub`` (2) as RFC 9943
  section 6 requires, payload hash algorithm (258) = -16 (SHA-256), preimage content type (259) =
  ``application/json`` (the preimage is the RFC 8785 JSON text), and payload location (260) only when
  the caller supplies one;
* unprotected: empty. A Transparency Service puts its receipts there (label 394) when it registers
  the statement.

No label stands in both buckets, none twice, label 3 (content type) in neither; 258, 259 and 260 only
in the protected header (RFC 9995 section 4); CWT Claims exactly once and protected. The encoding is
deterministic (RFC 8949 section 4.2.1): shortest heads, definite lengths, map keys in the bytewise
order of their encodings. The same key, bundle and arguments give the same bytes.

KEYS (owner decision B, 2026-09-27). EdDSA (-8) over Ed25519, the key of the receipt world, with a
protected ``kid``. By default the kid is the hexadecimal SHA-256 of the key's SubjectPublicKeyInfo,
ASCII, the self-binding measured on every CCF receipt (``scitt_ccf``). A kid only names a key; trust
comes from the relying party. The ``scitt-ccf/v1`` reader verifies statement keys selected by a
protected ``x5chain`` only (owner answer N7 b), so an EdDSA statement is outside that reader's
profile by design.

A statement says that the holder of the key signed this receipt root under this issuer and subject.
It says nothing about whether any recorded number is true, and without a receipt from a Transparency
Service it says nothing about registration.
"""
from __future__ import annotations

from typing import Any, Optional

from ._cbor_prescan import encode_head
from .errors import BundleFormatError, ProofBundleError

__all__ = ["MEDIA_TYPE", "ScittStatementError", "sign_statement"]

#: Label 259: the content type of the hash envelope's preimage, the RFC 8785 text of the receipt.
MEDIA_TYPE = "application/json"

_ALG, _KID, _CWT, _PAYLOAD_HASH_ALG, _PREIMAGE_CTY, _PAYLOAD_LOCATION = 1, 4, 15, 258, 259, 260
_CWT_ISS, _CWT_SUB = 1, 2
_EDDSA, _SHA256 = -8, -16


class ScittStatementError(BundleFormatError):
    """The producer refuses to write a statement: an argument it cannot write honestly, a bundle
    without a receipt root, or bytes that did not read back as written."""


def _enc(value: Any) -> bytes:
    """Deterministic CBOR (RFC 8949 section 4.2.1) for the few types a statement holds."""
    if isinstance(value, bool) or value is None:
        raise ScittStatementError(f"no deterministic encoding here for {type(value).__name__}")
    if isinstance(value, int):
        return encode_head(0, value) if value >= 0 else encode_head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return encode_head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return encode_head(3, len(raw)) + raw
    if isinstance(value, list):
        return encode_head(4, len(value)) + b"".join(_enc(v) for v in value)
    if isinstance(value, dict):
        items = sorted((_enc(k), _enc(v)) for k, v in value.items())
        if len({k for k, _v in items}) != len(items):
            raise ScittStatementError("two map keys with one encoding")
        return encode_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise ScittStatementError(f"no deterministic encoding here for {type(value).__name__}")


def _text(value: Any, what: str) -> str:
    """A non-empty text string that encodes as UTF-8 (no lone surrogate)."""
    if not isinstance(value, str) or not value:
        raise ScittStatementError(f"{what} must be a non-empty text string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ScittStatementError(f"{what} is not valid UTF-8 text") from None
    return value


def _receipt_root(bundle: Any) -> bytes:
    """The payload: the anchor root of a receipt that verifies."""
    if not isinstance(bundle, dict):
        raise ScittStatementError("the receipt must be a bundle (a JSON object)")
    from .anchors import receipt_canonical_root  # noqa: PLC0415
    from .bundle import verify_bundle  # noqa: PLC0415
    try:
        result = verify_bundle(bundle)
    except (ProofBundleError, ValueError, TypeError, RecursionError) as exc:
        raise ScittStatementError(f"the receipt cannot be verified: {type(exc).__name__}") from None
    if not result.ok:
        failed = [c.name for c in result.checks if not c.ok]
        raise ScittStatementError(f"the receipt does not verify (failed: {', '.join(failed)}); "
                                  "a statement over it would sign a root nobody can check")
    try:
        return receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})
    except (ProofBundleError, ValueError, RecursionError) as exc:
        raise ScittStatementError(f"the receipt has no canonical root: {exc}") from None


def _spki(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_statement(bundle: dict, signer, *, issuer: str, subject: str, kid: Optional[bytes] = None,
                   location: Optional[str] = None) -> bytes:
    """A tagged COSE_Sign1 hash envelope over ``bundle``'s receipt root, signed by ``signer``.

    ``signer`` is an Ed25519 private key (``emit.load_signer``); ``issuer`` and ``subject`` become the
    CWT ``iss`` and ``sub``; ``kid`` defaults to the hexadecimal SHA-256 of the signer's
    SubjectPublicKeyInfo; ``location`` becomes label 260. The bundle must verify. The bytes are read
    back with the ``scitt-ccf/v1`` reader and the signature checked before they are returned. Raises
    ``ScittStatementError`` for anything it cannot write honestly, ``scitt_ccf.ScittUnavailable``
    without the ``[scitt]`` extra.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    from . import scitt_ccf  # noqa: PLC0415
    if not isinstance(signer, Ed25519PrivateKey):
        raise ScittStatementError("the signer must be an Ed25519 private key (EdDSA, COSE alg -8)")
    issuer = _text(issuer, "issuer")
    subject = _text(subject, "subject")
    if location is not None:
        location = _text(location, "location")
    spki = _spki(signer.public_key())
    if kid is None:
        kid = scitt_ccf._derived_kid(spki)
    elif not isinstance(kid, (bytes, bytearray)) or not kid:
        raise ScittStatementError("kid must be a non-empty byte string")
    payload = _receipt_root(bundle)
    protected: dict = {_ALG: _EDDSA, _KID: bytes(kid), _CWT: {_CWT_ISS: issuer, _CWT_SUB: subject},
                       _PAYLOAD_HASH_ALG: _SHA256, _PREIMAGE_CTY: MEDIA_TYPE}
    if location is not None:
        protected[_PAYLOAD_LOCATION] = location
    protected_raw = _enc(protected)
    signature = signer.sign(scitt_ccf._sig_structure(protected_raw, payload))
    data = (encode_head(6, 18) + encode_head(4, 4) + _enc(protected_raw) + _enc({}) + _enc(payload)
            + _enc(signature))
    _read_back(data, protected, payload, signer.public_key())
    return data


def _read_back(data: bytes, protected: dict, payload: bytes, public_key) -> None:
    """The reader must see what was meant, and the signature must verify over what it sees."""
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415

    from . import scitt_ccf  # noqa: PLC0415
    st = scitt_ccf.decode_cose_sign1(data, role="statement")
    if not (st.tagged and st.unprotected == {} and st.payload == payload and st.protected == protected):
        raise ScittStatementError("the statement did not read back as written")
    try:
        public_key.verify(st.signature, scitt_ccf._sig_structure(st.protected_raw, st.payload))
    except InvalidSignature:
        raise ScittStatementError("the statement's signature does not verify over what was written") from None
